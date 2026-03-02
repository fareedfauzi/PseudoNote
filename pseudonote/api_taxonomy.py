# -*- coding: utf-8 -*-
import json
import os
import re
import logging
from typing import Dict, List, Set, Tuple, Union, Any, Optional

# Module-level taxonomy state variables
TAXONOMY_LOADED = False
API_MAP: Dict[str, Dict[str, str]] = {}
API_IGNORE: Set[str] = set()
API_IGNORE_CALLS: Set[str] = set()
COMBO_RULES: List[Dict[str, Any]] = []
CATEGORY_TO_SEVERITY: Dict[str, str] = {}

RISK_ORDER = {"pending": -1, "benign": 0, "suspicious": 1, "malicious": 2} # "pending" is UI state only
VALID_RISK_LEVELS = {"malicious", "suspicious", "benign", "pending"}
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

def normalize_risk_tag(risk_tag: Optional[str]) -> str:
    """Standardizes risk tags and defaults unknown values to 'benign'."""
    if not risk_tag or not isinstance(risk_tag, str):
        return "pending"
    tag = risk_tag.lower().strip()
    if tag in VALID_RISK_LEVELS:
        return tag
    return "benign" # Default for unknown analysis results

def load_api_taxonomy() -> Tuple[Dict[str, Dict[str, str]], Set[str], Set[str], List[Dict[str, Any]], Dict[str, str]]:
    """
    Load malware API taxonomy from JSON based on the new platform-specific schema.
    Also builds O(1) reverse lookup dicts for efficiency.
    Returns: (api_map, ignore, ignore_calls, combo_rules, category_to_severity)
    """
    global TAXONOMY_LOADED
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), "malware_api_tags.json"))
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        
        api_map = {}
        cat_to_sev = {}
        tags = data.get("TAGS", {})
        
        # Flatten all platform + cross-platform categories into one lookup dict
        # api_name_lower -> {"category": str, "severity": str, "platform": str}
        # Also build CATEGORY_TO_SEVERITY for O(1) severity lookups
        for platform, categories in tags.items():
            if not isinstance(categories, dict):
                continue
            for cat_name, cat_data in categories.items():
                if not isinstance(cat_data, dict):
                    continue
                
                # Cache severity mapping (Bug #4 fixed)
                severity = str(cat_data.get("severity", "LOW")).upper()
                cat_to_sev[cat_name] = severity
                
                for api in cat_data.get("apis", []):
                    # Keys must be stored lowercased for case-insensitivity consistency (Bug #6)
                    api_map[str(api).lower()] = {
                        "category": cat_name,
                        "severity": severity,
                        "platform": platform
                    }
        
        ignore = {str(a).lower() for a in data.get("TAGS_IGNORE_LIST", [])}
        ignore_calls = {str(a).lower() for a in data.get("IGNORE_CALL_LIST", [])}
        combo_rules = data.get("COMBINATION_RULES", [])
        
        if api_map or combo_rules or ignore:
            TAXONOMY_LOADED = True
            
        return api_map, ignore, ignore_calls, combo_rules, cat_to_sev
        
    except Exception as e:
        # Improved error context (Bug #3 fixed)
        cwd = os.getcwd()
        print(f"[PseudoNote] ERROR in load_api_taxonomy: Could not load taxonomy from {path}")
        print(f"[PseudoNote] Working directory: {cwd}. Exception: {e}")
        import traceback
        traceback.print_exc()
        TAXONOMY_LOADED = False
        return {}, set(), set(), [], {}

def is_taxonomy_healthy() -> Tuple[bool, str]:
    """
    Checks if the taxonomy was loaded successfully and contains data.
    Returns: (is_healthy, error_message)
    """
    if not TAXONOMY_LOADED:
        return False, "Taxonomy file failed to load or parse."
    if not API_MAP:
        return False, "Taxonomy loaded but API_MAP is empty."
    if not COMBO_RULES:
        return False, "Taxonomy loaded but COMBINATION_RULES are empty."
    return True, ""

def reload_taxonomy():
    """Force a reload of the taxonomy from disk."""
    global API_MAP, API_IGNORE, API_IGNORE_CALLS, COMBO_RULES, CATEGORY_TO_SEVERITY
    API_MAP, API_IGNORE, API_IGNORE_CALLS, COMBO_RULES, CATEGORY_TO_SEVERITY = load_api_taxonomy()
    return is_taxonomy_healthy()

# Initialize taxonomy on load
API_MAP, API_IGNORE, API_IGNORE_CALLS, COMBO_RULES, CATEGORY_TO_SEVERITY = load_api_taxonomy()

def get_category_severity(category: str) -> str:
    """
    Looks up category severity.
    O(1) lookup using the CATEGORY_TO_SEVERITY precomputed dict.
    """
    return CATEGORY_TO_SEVERITY.get(category, "LOW").upper()

def _extract_callees_list(ea: int, callees: Union[List[int], Dict[int, Any]]) -> List[int]:
    """Helper to safely extract a list of callee EAs from a polymorphic parameter."""
    if callees is None:
        return []
    
    # Bug #1 & #2 fixed: Handle if the caller passed a graph dict where ea is a key
    if isinstance(callees, dict):
        node = callees.get(ea)
        if node and hasattr(node, "callees") and node.callees:
            return list(node.callees)
        return []
        
    # Otherwise treat as list/iterable
    try:
        return list(callees)
    except TypeError:
        return []

def get_api_tags_for_function(ea: int, callees: Union[List[int], Dict[int, Any]], names_map: Optional[Dict[int, str]] = None) -> Dict[str, List[str]]:
    """
    Scans direct callees of a function using the malware taxonomy.
    
    Args:
        ea: Effective address of the function.
        callees: A list of callee EAs (analyzer.py usage), or a dict graph mapping {ea: FuncNode} (deep_analyzer.py usage).
        names_map: Optional dict of ea -> name to bypass IDA API queries.
        
    Returns:
        Dict mapping category name to list of API names triggered (preserves original casing).
    """
    # Defensive inline import for idc (Bug #2 fixed)
    try:
        import idc
    except ImportError:
        idc = None

    hits: Dict[str, List[str]] = {}
    callees_list = _extract_callees_list(ea, callees)
    
    # Use set to avoid redundant lookups or infinite loops from duplicates (Bug #5 partial)
    for callee_ea in set(callees_list):
        name = None
        if names_map is not None and callee_ea in names_map:
            name = names_map[callee_ea]
        elif idc is not None:
            try:
                import idaapi
                name = idaapi.execute_sync(lambda: idc.get_func_name(callee_ea), idaapi.MFF_READ)  # type: ignore
            except Exception as e:
                print(f"[PseudoNote] WARNING: get_func_name failed for ea {hex(callee_ea)}: {e}")
                continue
        
        if not name or not isinstance(name, str):
            continue
            
        # Case Insensitive Matching (Bug #6):
        # We lookup lowercased, but store the original case 'name' in hits 
        # so logs/outputs use the actual observed casing.
        name_lower = name.lower()
        
        # Strip common IDA thunk/import decorations before lookup
        for pfx in ("__imp_", "j_", "cs:", "ds:", "."):
            if name_lower.startswith(pfx):
                name_lower = name_lower[len(pfx):]
        if "@" in name_lower:
            name_lower = name_lower.split("@")[0]
            
        if name_lower in API_IGNORE or name_lower in API_IGNORE_CALLS:
            continue
            
        entry = API_MAP.get(name_lower)
        if entry:
            hits.setdefault(entry["category"], []).append(name)
            
    return hits

def evaluate_combination_rules(hits_dict: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """
    Takes the {category: [apis]} dict and evaluates COMBINATION_RULES logic.
    Returns list of triggered rule dicts.
    """
    triggered = []
    present_cats = set(hits_dict.keys())
    
    for rule in COMBO_RULES:
        requires = set(rule.get("requires", []))
        requires_any = set(rule.get("requires_any", []))
        also_has = set(rule.get("also_has", []))
        
        # "requires" = ALL must be present
        if requires and not requires.issubset(present_cats):
            continue
        # "requires_any" = at least one must be present
        if requires_any and not requires_any.intersection(present_cats):
            continue
        # If neither requires nor requires_any — skip (malformed rule)
        if not requires and not requires_any:
            continue
            
        triggered.append({
            "id": rule.get("id", "unknown"),
            "name": rule.get("name", "Unnamed Rule"),
            "severity": rule.get("severity", "LOW"),
            "description": rule.get("description", ""),
            "boosted": bool(also_has and also_has.intersection(present_cats))
        })
    return triggered

def derive_risk_from_api_tags(
    ea: int, 
    callees: Union[List[int], Dict[int, Any]], 
    names_map: Optional[Dict[int, str]] = None,
    detailed: bool = False
) -> Union[str, Tuple[str, int, str]]:
    """
    Derive a risk tag using malware_api_tags taxonomy + combination rules.
    
    Args:
        ea: Effective address of the central function
        callees: A list of callee EAs (analyzer.py) or a dict {ea: FuncNode} from the caller graph (deep_analyzer.py)
        names_map: Optional precomputed EA -> name mapping
        detailed: If True, returns a tuple of (risk_level, confidence, reason). 
                  If False, strictly returns a string risk_level (for backwards compatibility).
        
    Returns:
        Risk level string: 'malicious', 'suspicious', or 'benign' (if detailed=False).
        Or Tuple[str, int, str]: (risk_level, confidence, reason) (if detailed=True).
    """
    # Handled taxonomy not loaded failure gracefully
    if not TAXONOMY_LOADED:
        return ("benign", 0, "insufficient_data (taxonomy missing)") if detailed else "benign"

    callees_list = _extract_callees_list(ea, callees)
    
    # Bug #5 Edge case: No data for evaluation
    if not callees_list:
        return ("benign", 0, "insufficient_data (no callees to analyze)") if detailed else "benign"

    hits = get_api_tags_for_function(ea, callees_list, names_map)
    
    # Confirmed parsed but no bad hits found
    if not hits:
        return ("benign", 80, "confirmed_benign") if detailed else "benign"

    max_sev = 0
    trigger_reasons = []

    for cat in hits.keys():
        sev = get_category_severity(cat)
        max_sev = max(max_sev, SEVERITY_ORDER.get(sev, 0))
        trigger_reasons.append(f"API Category: {cat}")

    combos = evaluate_combination_rules(hits)
    for combo in combos:
        sev = str(combo.get("severity", "LOW")).upper()
        if combo.get("boosted") and sev == "MEDIUM":
            sev = "HIGH"
        max_sev = max(max_sev, SEVERITY_ORDER.get(sev, 0))
        trigger_reasons.append(f"Rule: {combo.get('name')}")

    reason_str = "; ".join(trigger_reasons)

    if max_sev >= 2:
        return ("malicious", 90, reason_str) if detailed else "malicious"
    if max_sev == 1:
        return ("suspicious", 70, reason_str) if detailed else "suspicious"
    
    return ("benign", 80, reason_str) if detailed else "benign"
