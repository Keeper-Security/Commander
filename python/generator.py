from random import sample

ASCII = (
    'abcdefghijklmnopqrstuvwxyz' + \
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ' + \
    '01234567890' + \
    '.{}[];!@#$%^&*()=:></?'
)

ALPHNUM = (
    'abcdefghijklmnopqrstuvwxyz' + \
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ' + \
    '0123456789'
)

def generate(length=64, chars=ASCII):
    """ Generate password of variable len """
    return ''.join(sample(chars, length))

