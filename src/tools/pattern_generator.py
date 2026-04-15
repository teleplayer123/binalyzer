from typing import Tuple, List

def get_chars(r: Tuple[int,int]) -> List[str]:
    chars = []
    for i in range(r[0],r[1]):
        chars.append(chr(i))
    return chars

def create_pattern(length: int) -> str:
    alphaUpper = get_chars((65, 91))
    alphaLowwer = get_chars((97, 123))
    nums = get_chars((48, 58))
    pattern = ""
    for i in range(len(alphaUpper)):
        if len(pattern) >= length:
            break
        for j in range(len(alphaLowwer)):
            if len(pattern) >= length:
                break
            for k in range(len(nums)):
                pattern += "%s%s%s" %(alphaUpper[i], alphaLowwer[j], nums[k])
                if len(pattern) >= length:
                    break
    if len(pattern) > length:
        trunc = len(pattern) - length
        pattern = pattern[:-trunc]
    return pattern

def pattern_offset(val: str, length: int) -> int:
    pattern = str(create_pattern(length))
    return pattern.index(str(val))

def generate_pattern(length: int) -> str:
    pattern = create_pattern(length)
    return pattern
