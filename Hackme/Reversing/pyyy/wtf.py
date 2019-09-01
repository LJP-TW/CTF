# l = (lambda f: (lambda x: x(x))(lambda y: f(lambda *args: y(y)(*args))))(lambda f: lambda x: 1 if x < 2 else f(x - 1) * x % n)(g % 27777)


stage = 0
# Init Stage 0
__import__('sys').setrecursionlimit(1048576)

f = 138429774382724799266162638867586769792748493609302140496533867008095173455879947894779596310639574974753192434052788523153034589364467968354251594963074151184337695885797721664543377136576728391441971163150867881230659356864392306243566560400813331657921013491282868612767612765572674016169587707802180184907L
m = 8804961678093749244362737710317041066205860704668932527558424153061050650933657852195829452594083176433024286784373401822915616916582813941258471733233011L
g = 67051725181167609293818569777421162357707866659797065037224862389521658445401L

n = pow(f, m, g)

l = (lambda f: (lambda x: x(x))(lambda y: f(lambda *args: y(y)(*args))))(lambda f: lambda x: 1 if x < 2 else f(x - 1) * x % n)(g % 27777)
print('stage %d: %d' % (stage, l))
stage += 1

#### Stage 1
l1 = lambda f: (lambda x: x(x))(lambda y: f(lambda *args: y(y)(*args)))
l2 = lambda f: lambda x: 1 if x < 2 else f(x - 1) * x % n
# g % 27777 = 5930

l = l1(l2)(5930)
print('stage %d: %d' % (stage, l))
stage += 1

#### Stage 2
l11 = lambda x: x(x)
l1 = lambda f: l11(lambda y: f(lambda *args: y(y)(*args)))
l1 = lambda f: ( lambda y: f(lambda *args: y(y)(*args)) )( lambda y: f(lambda *args: y(y)(*args)) )
l2 = lambda f: lambda x: 1 if x < 2 else f(x - 1) * x % n

l = l1(l2)(5930)
print('stage %d: %d' % (stage, l))
stage += 1

#### Stage 3
l2 = lambda f: lambda x: 1 if x < 2 else f(x - 1) * x % n
l1 = (lambda y: 
        l2(lambda *args: 
            y(y)(*args)
        )
     )(lambda y: 
        l2(lambda *args: 
            y(y)(*args)
        )
     )

l = l1(5930)
print('stage %d: %d' % (stage, l))
stage += 1

#### Stage 4
l2 = lambda f: lambda x: 1 if x < 2 else f(x - 1) * x % n
l11 = (lambda y:
         l2(lambda *args:
             y(y)(*args)
         )
      )
l1 = l11(l11)

l = l1(5930)
print('stage %d: %d' % (stage, l))
stage += 1

#### Stage 5
l2 = lambda f: lambda x: 1 if x < 2 else f(x - 1) * x % n
l11 = (lambda y:
         l2(lambda *args:
             y(y)(*args)
         )
      )
l1 = l2(lambda *args:
         l11(l11)(*args)
     )

l = l1(5930)
l = l2(lambda *args:
         l11(l11)(*args)
    )(5930)

l3 = lambda *args: l11(l11)(*args)
l = l2(l3)(5930)

print('stage %d: %d' % (stage, l))
stage += 1

#### Stage 6
l2 = lambda f: lambda x: 1 if x < 2 else f(x - 1) * x % n
l11 = (lambda y:
         l2(lambda *args:
             y(y)(*args)
         )
      )
l3 = lambda *args: l11(l11)(*args)
l = l2(l3)(5930)
l = 1 if 5930 < 2 else l3(5929) * 5930 % n
l = l3(5929) * 5930 % n

print('stage %d: %d' % (stage, l))
stage += 1

#### Stage 7
l2 = lambda f: lambda x: 1 if x < 2 else f(x - 1) * x % n
l11 = (lambda y:
         l2(lambda *args:
             y(y)(*args)
         )
      )
l3 = lambda *args: l11(l11)(*args)
l = l3(5929) * 5930 % n
l = l11(l11)(5929) * 5930 % n

print('stage %d: %d' % (stage, l))
stage += 1

#### Stage 8
l2 = lambda f: lambda x: 1 if x < 2 else f(x - 1) * x % n
l11 = (lambda y:
         l2(lambda *args:
             y(y)(*args)
         )
      )
l3 = lambda *args: l11(l11)(*args)
l = l11(l11)(5929) * 5930 % n
l = l2(lambda *args: l11(l11)(*args))(5929) * 5930 % n
l = l2(l3)(5929) * 5930 % n
l = (1 if 5929 < 2 else l3(5928) * 5929 % n) * 5930 % n
l = (l3(5928) * 5929 % n) * 5930 % n

print('stage %d: %d' % (stage, l))
stage += 1

