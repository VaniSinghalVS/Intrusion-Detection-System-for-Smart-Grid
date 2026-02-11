from collections import deque
import numpy as np

class EWMA:
    def __init__(self, alpha=0.3, maxlen=200):
        self.alpha, self.y = alpha, None
        self.buf = deque(maxlen=maxlen)

    def update_and_is_outlier(self, x, k=3.5):
        self.buf.append(x)
        self.y = x if self.y is None else self.alpha*x + (1-self.alpha)*self.y
        arr = np.array(self.buf, dtype=float)
        med = np.median(arr)
        mad = np.median(np.abs(arr - med)) + 1e-6
        lo, hi = self.y - k*mad, self.y + k*mad
        return x < lo or x > hi
