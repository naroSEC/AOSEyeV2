def decode_java_text(value):
    """JSON object hook: preserve Java strings that Jython cannot represent."""
    if set(value) == {'__aoseye_utf16_codepoints__'}:
        return ''.join(chr(point) for point in value['__aoseye_utf16_codepoints__'])
    return value
