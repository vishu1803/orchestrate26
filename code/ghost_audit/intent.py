"""Deletion authorization boundary. Ambiguity must remain explicit internally."""
from dataclasses import dataclass
from typing import Literal
import re
import unicodedata


@dataclass(frozen=True)
class IntentDecision:
    authorization: Literal["AUTHORIZED", "OTHER_REQUEST", "UNRESOLVED"]
    supporting_text: str
    reason: str = ""


def classify_intent(request_text: str) -> IntentDecision:
    """Classify multilingual deletion intent; do not trust workflow status."""
    text = unicodedata.normalize("NFKC", request_text).strip()
    if not text:
        return IntentDecision("UNRESOLVED", "", "empty_request")
    # Negation and information requests take precedence over mere deletion words.
    negative = (
        r"\b(?:do not|don't|not asking for|not a request to|without)\s+(?:\w+\s+){0,3}(?:delet\w*|eras\w*|remov\w*|clos\w*)",
        r"\b(?:how (?:do|can|to)|what (?:happens if|does|would)|explain how|tell me how)\b[^.!?]{0,60}\b(?:delet|eras|clos)",
        r"\b(?:no (?:quiero|solicito|borres|elimines)|sin (?:borrar|eliminar))\b",
        r"\b(?:n[aã]o (?:quero|solicito|apague|exclua)|sem (?:apagar|excluir))\b",
        r"\bne\b[^.!?]{0,40}\b(?:supprim\w*|effac\w*)\s+pas\b",
        r"(?:削除しない|削除しないで|삭제하지\s*마|삭제를?\s*원하지\s*않)",
    )
    for pattern in negative:
        match = re.search(pattern, text, re.I)
        if match:
            tail = text[match.end():].split(".", 1)[0]
            if re.match(r"\s*(?:the |my |any )?(?:invoices|security|legal|backups|retained)\b", tail, re.I):
                continue
            return IntentDecision("OTHER_REQUEST", match.group(), "explicit_non_deletion_or_inquiry")
    inquiry = re.search(r"\b(?:what|how|why|explain)\b[^.!?]{0,60}\b(?:retention|privacy policy|retain|deletion policy)\b", text, re.I)
    if inquiry:
        return IntentDecision("OTHER_REQUEST", inquiry.group(), "privacy_or_retention_inquiry")
    # Imperative/first-person deletion, plus explicit auditing of an existing
    # deletion request. Object words prevent 'delete a newsletter' authorizing
    # an unrelated account-wide deletion.
    positive = (
        r"\b(?:delete|erase|remove|close|deleting)\b[^.!?]{0,100}\b(?:account|profile|personal|records|addresses|identifiers|search result|export|attachment)\b",
        r"\b(?:account|profile|personal (?:data|information)|records)\b[^.!?]{0,100}\b(?:to be (?:deleted|erased|closed|removed)|deleting)\b",
        r"\b(?:request|requesting|want|ask for|asking for|would like)\b[^.!?]{0,40}\b(?:deletion|erasure)\b",
        r"\bplease\s+(?:process|begin|submit|start)\b[^.!?]{0,80}\b(?:deletion|erasure)\b",
        r"\b(?:would like|want|request)\b[^.!?]{0,60}\b(?:it|account|profile|data|information)\s+(?:permanently\s+)?(?:deleted|erased|closed|removed)\b",
        r"\b(?:finish|complete|audit|verify|confirm)\b[^.!?]{0,80}\b(?:deletion|eliminaci[oó]n)\b",
        r"\b(?:please|can you|could you|would you)\b[^.!?]{0,35}\b(?:verify|confirm|check|inspect|review)\b[^.!?]{0,180}\b(?:deleted|gone|removed|retained|identify)\b",
        r"\b(?:solicito|solicitar|quiero|pueden|intent[eé])\b[^.!?]{0,100}\b(?:elimin\w*|borrar|supresi[oó]n)\b",
        r"\b(?:solicito|quero|pe[cç]o)\b[^.!?]{0,100}\b(?:exclus[aã]o|excluir|apagar|elimina[cç][aã]o)\b",
        r"\b(?:je demande|je souhaite|veuillez|merci de)\b[^.!?]{0,100}\b(?:suppression|supprim\w*|effac\w*)\b",
        r"(?:アカウント|個人情報)[^。！？]{0,80}削除[^。！？]{0,40}(?:依頼|お願い|ください|希望)",
        r"(?:계정|개인정보)[^.?!]{0,80}삭제[^.?!]{0,40}(?:요청|주세요|원합니다)",
    )
    for pattern in positive:
        match = re.search(pattern, text, re.I)
        if match:
            return IntentDecision("AUTHORIZED", match.group(), "explicit_deletion_or_deletion_audit")
    # A request to clean up a previously deleted subject may refer back with
    # 'them'/'the rest'. History alone still cannot authorize an export request.
    history = re.search(r"\b(?:account|profile|personal (?:data|details))\b", text, re.I)
    deleted = re.search(r"\b(?:deleted|deletion|gone|closed)\b", text, re.I)
    cleanup = re.search(r"\b(?:please|can you|could you)\b[^.!?]{0,100}\b(?:handle|remove|redact|erase|clean|disable|block)\b", text, re.I)
    if history and deleted and cleanup:
        return IntentDecision("AUTHORIZED", cleanup.group(), "requested_cleanup_of_prior_deletion")
    other = re.search(r"\b(?:access|download|export|copy|correct|correction|update|replace|change|misspelled|marketing|promotional|unsubscribe|opt.out|retention|privacy|information request)\b|(?:acceso|copia|corregir|exportar|acesso|c[oó]pia|corrigir|t[eé]l[eé]charg|rectifi|acc[eè]s|정보.*(?:열람|수정|내보내기)|開示|訂正|エクスポート)", text, re.I)
    if other:
        return IntentDecision("OTHER_REQUEST", other.group(), "access_correction_export_or_opt_out")
    return IntentDecision("UNRESOLVED", "", "unrecognized_or_ambiguous_request")


def classify_request_intent(request) -> IntentDecision:
    return classify_intent(request.request_text)
