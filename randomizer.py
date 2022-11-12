class RandGenerator():
    def __init__(self, m = 2**31, a = 9**5, c = 1, x0 = 5):
        self.m = m
        self.a = a
        self.c = c
        self.x = x0

    def generate(self, m, a, c, x):
        xn = (x*a + c) % m
        return xn

    def next(self):
        x = self.x
        self.x = self.generate(self.m, self.a, self.c, self.x)
        return x