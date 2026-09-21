"""A small provider boundary; normal monitoring never depends on this module."""
from __future__ import annotations
import ipaddress, json, logging, random, socket, time, urllib.parse
from datetime import datetime, timedelta, timezone
from app.ai.prompts import SYSTEM_PROMPT, LANGUAGE_INSTRUCTIONS
from app.config import AI_TI_ENABLED, AI_TI_MAX_REQUESTS_PER_MINUTE, AI_TI_RETRY_ATTEMPTS, AI_TI_RETRY_BASE_DELAY, AI_TI_TIMEOUT_SECONDS, AI_TI_PROVIDER_COOLDOWN_SECONDS, GEMINI_API_KEY, GEMINI_API_KEYS, GEMINI_MODEL
from app.models.alert import AIThreatInvestigation
from app.services.threat_intelligence import normalize

ASSESSMENTS={"MALICIOUS","SUSPICIOUS","BENIGN","UNKNOWN","INSUFFICIENT_EVIDENCE"}
logger=logging.getLogger(__name__)
class ProviderError(RuntimeError):
    def __init__(self, status_code, error_type, message, retryable=False, attempts=1):
        super().__init__(message); self.data={"provider":"gemini","status_code":status_code,"error_type":error_type,"retryable":retryable,"attempts":attempts,"message":message}

class GeminiProviderManager:
    """Backend-only key selection for legitimate configured deployments, never quota bypassing."""
    def __init__(self, keys=None):
        raw = keys if keys is not None else (GEMINI_API_KEYS or ([GEMINI_API_KEY] if GEMINI_API_KEY else []))
        self.providers=[{"id":f"gemini-{i + 1}","key":key,"until":0.0,"invalid":False} for i,key in enumerate(raw)]
    def available(self):
        now=time.monotonic(); return [p for p in self.providers if not p["invalid"] and p["until"] <= now]
    def mark_failure(self, provider, status):
        if status in (401,403,404): provider["invalid"] = True
        elif status in (429,500,502,503,504,None): provider["until"] = time.monotonic() + AI_TI_PROVIDER_COOLDOWN_SECONDS
        logger.warning("Gemini provider attempt provider_id=%s status=%s", provider["id"], status)

def _category(status):
    return {400:("invalid_request",False,"Invalid AI investigation request."),401:("authentication",False,"Gemini authentication problem."),403:("authentication",False,"Gemini authentication problem."),404:("model_configuration",False,"Gemini model configuration problem."),429:("quota_limit",True,"Gemini quota or rate limit reached."),500:("provider_unavailable",True,"Gemini service temporarily unavailable."),502:("provider_unavailable",True,"Gemini service temporarily unavailable."),503:("provider_unavailable",True,"Gemini service temporarily unavailable."),504:("provider_unavailable",True,"Gemini service temporarily unavailable.")}.get(status,("provider_error",False,"AI investigation failed."))
class AIThreatInvestigator:
    def investigate(self, indicator_type:str, indicator_value:str, reason:str|None, language:str="en"): raise NotImplementedError

class GeminiThreatInvestigator(AIThreatInvestigator):
    def __init__(self, manager=None): self.manager=manager or GeminiProviderManager()
    @staticmethod
    def _request_url(api_key=None):
        # The documented REST path needs one model name, not ``models/models/...``.
        model = GEMINI_MODEL.removeprefix("models/").strip()
        if not model or "/" in model: raise RuntimeError("Invalid GEMINI_MODEL configuration")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        # Keep the credential in the HTTPS query as documented for Gemini's
        # REST API. It is intentionally never logged or returned to callers.
        return f"{url}?key={urllib.parse.quote(api_key, safe='')}" if api_key else url

    @staticmethod
    def _error_detail(exc):
        try:
            payload = json.loads(exc.read().decode("utf-8", errors="replace"))
            return str(payload.get("error", {}).get("message", "")).replace("\n", " ")[:500]
        except Exception:
            return "no error detail was returned by the provider"

    def investigate(self, indicator_type, indicator_value, reason, language="en"):
        if language not in LANGUAGE_INSTRUCTIONS: raise ValueError("Unsupported investigation language")
        if not AI_TI_ENABLED or not self.manager.providers: raise RuntimeError("AI investigation is disabled or no Gemini key is configured")
        import urllib.error, urllib.parse, urllib.request
        body={"systemInstruction":{"parts":[{"text":SYSTEM_PROMPT + "\n" + LANGUAGE_INSTRUCTIONS[language]}]},"contents":[{"parts":[{"text":json.dumps({"indicator_type":indicator_type,"indicator_value":indicator_value,"reason_for_investigation":reason,"language":language})}]}],"generationConfig":{"responseMimeType":"application/json"}}
        attempts=0
        for provider in self.manager.available():
            headers={"Content-Type":"application/json"}
            for attempt in range(AI_TI_RETRY_ATTEMPTS + 1):
                attempts += 1
                request=urllib.request.Request(self._request_url(provider["key"]),data=json.dumps(body).encode(),headers=headers)
                try:
                    with urllib.request.urlopen(request,timeout=AI_TI_TIMEOUT_SECONDS) as response: raw=json.loads(response.read())
                    text=raw["candidates"][0]["content"]["parts"][0]["text"]
                    result=validate_result(json.loads(text), GEMINI_MODEL, indicator_type, indicator_value)
                    result["limitations"] = list(result["limitations"]) + ["This investigation did not use web grounding; independently verify any AI-generated claims and sources."]
                    logger.info("AI investigation completed provider_id=%s attempts=%d", provider["id"], attempt + 1)
                    return result
                except urllib.error.HTTPError as exc:
                    detail=self._error_detail(exc); error_type,retryable,message=_category(exc.code)
                    self.manager.mark_failure(provider, exc.code)
                    if exc.code in (500,502,503,504) and attempt < AI_TI_RETRY_ATTEMPTS:
                        time.sleep(AI_TI_RETRY_BASE_DELAY*(2**attempt)+random.uniform(0,0.5)); continue
                    if exc.code in (400,401,403,404):
                        raise ProviderError(exc.code,error_type,f"{message} {detail}",False,attempts) from exc
                    break
                except urllib.error.URLError:
                    self.manager.mark_failure(provider, None); break
                except (KeyError, json.JSONDecodeError, ValueError) as exc:
                    raise RuntimeError("Gemini returned an unusable investigation result. Try again later.") from exc
        raise ProviderError(None,"provider_unavailable","AI investigation is temporarily unavailable.",True,attempts)

def validate_result(data, model, indicator_type=None, indicator_value=None):
    if not isinstance(data,dict) or data.get("assessment") not in ASSESSMENTS: raise ValueError("Malformed AI assessment")
    confidence=float(data.get("confidence",0));
    if not 0 <= confidence <= 1: raise ValueError("AI confidence must be 0..1")
    assessment=data["assessment"]; limitations=[str(item) for item in data.get("limitations",[]) if str(item).strip()]
    evidence=[item for item in data.get("evidence",[]) if isinstance(item,(str,dict))]
    sources=[]
    for item in data.get("sources",[]):
        candidate=item if isinstance(item,str) else item.get("source_url","") if isinstance(item,dict) else ""
        parsed=urllib.parse.urlparse(candidate)
        if parsed.scheme in {"http","https"} and parsed.netloc: sources.append(candidate)
    if assessment in {"BENIGN","SUSPICIOUS","MALICIOUS"} and not limitations:
        limitations.append("This assessment is limited to the supplied evidence and is not a definitive reputation or behavioral conclusion.")
    if indicator_type in {"IPV4","IPV6"}:
        try: private=ipaddress.ip_address(indicator_value).is_private
        except ValueError: private=False
        if private:
            if assessment == "BENIGN": assessment="UNKNOWN"
            confidence=min(confidence,.6)
            limitations.append("Private/non-routable addressing does not establish that a host or its activity is benign; public reputation may not apply.")
    return {"assessment":assessment,"confidence":confidence,"summary":str(data.get("summary","")),"evidence":evidence,"sources":sources,"limitations":limitations,"model":model}

class InvestigationService:
    def __init__(self,db,provider=None): self.db,self.provider=db,provider or GeminiThreatInvestigator()
    def create(self,data):
        language=data.get("language","en").lower()
        if language not in LANGUAGE_INSTRUCTIONS: raise ValueError("language must be en or am")
        kind=data["indicator_type"].upper(); value=normalize(data["indicator_value"],kind)
        recent=self.db.query(AIThreatInvestigation).filter_by(indicator_type=kind,indicator_value=value).filter(AIThreatInvestigation.status.in_(["RUNNING", "COMPLETED"])).filter(AIThreatInvestigation.created_at>datetime.now(timezone.utc)-timedelta(minutes=5)).first()
        if recent: return recent
        count=self.db.query(AIThreatInvestigation).filter(AIThreatInvestigation.created_at>datetime.now(timezone.utc)-timedelta(minutes=1)).count()
        if count>=AI_TI_MAX_REQUESTS_PER_MINUTE: raise ValueError("AI investigation rate limit reached; try again shortly")
        row=AIThreatInvestigation(indicator_type=kind,indicator_value=value,reason=data.get("reason"),language=language,incident_id=data.get("incident_id"),status="RUNNING");self.db.add(row);self.db.commit()
        try:
            result=self.provider.investigate(kind,value,row.reason,language); row.status="COMPLETED"; row.assessment=result["assessment"];row.confidence=result["confidence"];row.summary=result["summary"];row.evidence=json.dumps(result["evidence"]);row.sources=json.dumps(result["sources"]);row.limitations=json.dumps(result["limitations"]);row.model=result["model"];row.completed_at=datetime.now(timezone.utc)
        except ProviderError as exc: row.status="FAILED";row.error=json.dumps(exc.data)
        except Exception as exc: row.status="FAILED";row.error=json.dumps({"provider":"gemini","status_code":None,"error_type":"internal","retryable":False,"attempts":1,"message":"AI investigation failed."})
        self.db.commit();self.db.refresh(row);return row
