#!/usr/bin/env python3
import os
import logging
import yara

YARA_RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_rules")

logger = logging.getLogger("YARA-Scanner")

_compiled_rules = None


def _get_rules():
    global _compiled_rules
    if _compiled_rules:
        return _compiled_rules
    try:
        rule_files = {
            os.path.splitext(f)[0]: os.path.join(YARA_RULES_DIR, f)
            for f in os.listdir(YARA_RULES_DIR)
            if f.endswith((".yar", ".yara"))
        }
        if not rule_files:
            logger.warning("No YARA rule files found in " + YARA_RULES_DIR)
            return None
        _compiled_rules = yara.compile(filepaths=rule_files)
        logger.info(f"Compiled {len(rule_files)} YARA rule file(s)")
        return _compiled_rules
    except Exception as e:
        logger.error(f"YARA compile failed: {e}")
        return None


def scan_with_yara(file_list):
    suspicious = []
    rules = _get_rules()
    if not rules:
        return suspicious

    def _check(filepath):
        try:
            matches = rules.match(filepath, timeout=30)
            if matches:
                logger.warning(f"YARA hit on {filepath}: {[m.rule for m in matches]}")
                return filepath
        except yara.TimeoutError:
            logger.warning(f"YARA timeout on {filepath}")
        except Exception as e:
            logger.error(f"YARA scan error on {filepath}: {e}")
        return None

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=4) as ex:
        results = ex.map(_check, file_list)

    return [f for f in results if f is not None]
