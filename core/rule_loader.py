"""
Module Rule Loader - Bài tập 3
Đọc file .rules, bỏ dòng trống và comment.
Chuyển rule hợp lệ về Rule Parser & Validator.
Cho phép enable/disable rule. Lỗi một rule không làm dừng các rule khác.
"""

import os
from core.rule_parser import parse_rule


def load_rules_from_file(filepath):
    """
    Đọc một file .rules và parse từng rule.
    Trả về (valid_rules, invalid_rules, unsupported_rules, stats).
    """
    valid_rules = []
    invalid_rules = []
    unsupported_rules = []
    stats = {
        "total_lines": 0,
        "blank_lines": 0,
        "comment_lines": 0,
        "rule_lines": 0,
        "valid": 0,
        "invalid": 0,
        "unsupported": 0,
        "disabled": 0,
        "file": filepath
    }

    if not os.path.exists(filepath):
        print(f"[RuleLoader] WARNING: File not found: {filepath}")
        return valid_rules, invalid_rules, unsupported_rules, stats

    print(f"[RuleLoader] Loading rules from: {filepath}")

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            stats["total_lines"] += 1
            line = line.strip()

            # Bỏ dòng trống
            if not line:
                stats["blank_lines"] += 1
                continue

            # Bỏ comment (bắt đầu bằng #)
            if line.startswith('#'):
                stats["comment_lines"] += 1

                # Kiểm tra disabled rule (comment-out rule)
                # VD: # alert tcp any any -> any any (msg:"disabled"; sid:999;)
                stripped = line.lstrip('#').strip()
                if stripped and any(stripped.startswith(act) for act in
                                   ["alert ", "log ", "pass ", "drop ", "reject ", "sdrop "]):
                    stats["disabled"] += 1
                continue

            stats["rule_lines"] += 1

            # Parse rule
            try:
                rule_obj = parse_rule(line)

                if rule_obj.status == "valid":
                    valid_rules.append(rule_obj)
                    stats["valid"] += 1
                elif rule_obj.status == "unsupported":
                    unsupported_rules.append(rule_obj)
                    stats["unsupported"] += 1
                    print(f"  [!] Line {line_num}: UNSUPPORTED - {rule_obj.status_reason}")
                else:  # invalid
                    invalid_rules.append(rule_obj)
                    stats["invalid"] += 1
                    print(f"  [!] Line {line_num}: INVALID - {rule_obj.status_reason}")

            except Exception as e:
                stats["invalid"] += 1
                print(f"  [!] Line {line_num}: ERROR - {str(e)}")

    print(f"[RuleLoader] Results: {stats['valid']} valid, "
          f"{stats['invalid']} invalid, "
          f"{stats['unsupported']} unsupported, "
          f"{stats['disabled']} disabled, "
          f"{stats['comment_lines']} comments, "
          f"{stats['blank_lines']} blank")

    return valid_rules, invalid_rules, unsupported_rules, stats


def load_rules_from_directory(dirpath, pattern="*.rules"):
    """Đọc tất cả file .rules trong thư mục."""
    import glob

    all_valid = []
    all_invalid = []
    all_unsupported = []
    all_stats = []

    rule_files = glob.glob(os.path.join(dirpath, pattern))
    if not rule_files:
        print(f"[RuleLoader] No rule files found in: {dirpath}")
        return all_valid, all_invalid, all_unsupported, all_stats

    for filepath in sorted(rule_files):
        valid, invalid, unsupported, stats = load_rules_from_file(filepath)
        all_valid.extend(valid)
        all_invalid.extend(invalid)
        all_unsupported.extend(unsupported)
        all_stats.append(stats)

    print(f"[RuleLoader] Total: {len(all_valid)} valid rules from {len(rule_files)} files")
    return all_valid, all_invalid, all_unsupported, all_stats


def load_rules(paths):
    """
    Load rules từ danh sách đường dẫn (file hoặc thư mục).
    Trả về (valid_rules, invalid_rules, unsupported_rules, all_stats).
    """
    all_valid = []
    all_invalid = []
    all_unsupported = []
    all_stats = []

    if isinstance(paths, str):
        paths = [paths]

    for path in paths:
        if os.path.isdir(path):
            valid, invalid, unsupported, stats = load_rules_from_directory(path)
            all_valid.extend(valid)
            all_invalid.extend(invalid)
            all_unsupported.extend(unsupported)
            if isinstance(stats, list):
                all_stats.extend(stats)
            else:
                all_stats.append(stats)
        elif os.path.isfile(path):
            valid, invalid, unsupported, stats = load_rules_from_file(path)
            all_valid.extend(valid)
            all_invalid.extend(invalid)
            all_unsupported.extend(unsupported)
            all_stats.append(stats)
        else:
            print(f"[RuleLoader] WARNING: Path not found: {path}")

    return all_valid, all_invalid, all_unsupported, all_stats
