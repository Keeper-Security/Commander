def value_to_boolean(value):
    value = str(value)
    if value.lower() in ['true', 'yes', 'on', '1']:
        return True
    elif value.lower() in ['false', 'no', 'off', '0']:
        return False
    else:
        return None
