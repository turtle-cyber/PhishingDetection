# text_utils.py
import math
from collections import Counter

def shannon_entropy(s):
    if not s:
        return 0.0
    probs = [n/len(s) for n in Counter(s).values()]
    return -sum(p*math.log2(p) for p in probs)

def top_ngrams(s, n=3, topn=5):
    s = s.lower()
    grams = [s[i:i+n] for i in range(len(s)-n+1)]
    c = Counter(grams)
    return c.most_common(topn)
