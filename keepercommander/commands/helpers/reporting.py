import re

""" Filter rows by pattern(s). All non-primitive data type values contained are assumed to be of type List """
def filter_rows(rows, patterns, use_regex=False, match_all=False):
    if not patterns:
        return rows

    is_a = lambda o, t: isinstance(o, t)
    to_string = lambda el: el if is_a(el, str) else is_a(el, list) and ' '.join([to_string(c) for c in el]) or str(el) or ''
    
    def create_pattern_matcher(pattern_str):
        """Create a matcher function for a single pattern with prefix support"""
        pattern_str = str(pattern_str).strip()
        
        if pattern_str.startswith('regex:'):
            regex_pattern = pattern_str[6:]  # Remove 'regex:' prefix
            try:
                compiled_regex = re.compile(regex_pattern, re.IGNORECASE)
                return lambda text: bool(compiled_regex.search(text))
            except re.error as e:
                return lambda text: regex_pattern.lower() in text.lower()
        
        elif pattern_str.startswith('exact:'):
            exact_pattern = pattern_str[6:]  # Remove 'exact:' prefix
            return lambda text: text.lower() == exact_pattern.lower()
        
        elif pattern_str.startswith('not:'):
            not_pattern = pattern_str[4:]  # Remove 'not:' prefix
            if not_pattern.startswith('regex:'):
                # Negated regex
                regex_pattern = not_pattern[6:]
                try:
                    compiled_regex = re.compile(regex_pattern, re.IGNORECASE)
                    return lambda text: not bool(compiled_regex.search(text))
                except re.error:
                    return lambda text: regex_pattern.lower() not in text.lower()
            elif not_pattern.startswith('exact:'):
                # Negated exact match
                exact_pattern = not_pattern[6:]
                return lambda text: text.lower() != exact_pattern.lower()
            else:
                # Negated substring match
                return lambda text: not_pattern.lower() not in text.lower()
        
        else:
            if use_regex:
                try:
                    compiled_regex = re.compile(pattern_str, re.IGNORECASE)
                    return lambda text: bool(compiled_regex.search(text))
                except re.error:
                    return lambda text: pattern_str.lower() in text.lower()
            else:
                return lambda text: pattern_str.lower() in text.lower()
    
    pattern_matchers = []
    for pattern in patterns:
        matcher = create_pattern_matcher(pattern)
        pattern_matchers.append(matcher)
    
    def is_match(row):
        """Check if row matches according to the specified logic"""
        row_text = to_string(row)
        results = []
        
        for matcher in pattern_matchers:
            match_result = matcher(row_text)
            results.append(match_result)
        
        # Apply AND/OR logic
        if match_all:
            return all(results)
        else:
            return any(results)
    
    return list(filter(lambda row: is_match(row), rows))
