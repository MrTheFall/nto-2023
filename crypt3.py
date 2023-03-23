import ast
from Crypto.Util.number import long_to_bytes
from factordb import factordb
# импорт библиотек


def read_ct():
    with open('data.txt', 'r') as f:
        for line in f:
            yield ast.literal_eval(line)
            # открытие и чтение data.txt

# https://www.ctfnote.com/crypto/rsa/prime-factors
def fdb(x):
    f = factordb.FactorDB(x)
    f.connect()
    # коннект к фактору
    return f.get_factor_list()
    # факторизация через базовый sage модкль


def dislog(f, p, ct):
    F = GF(p, proof=False)
    # Galois field/Конечное поле
    power = p // f
    # целочисл. показат.
    return int(discrete_log(F(ct)^power, F(2)^power, ord=f))
    # дискретное логарифмирование


def main():
    factors, results = [], []
    for x in read_ct():
        p, ct = x['p'], x['shared_flag']
        for f in fdb(p-1):
        # те самые p-1
            if 10 <= f.bit_length() < 20:
                print(f)
                factors.append(f)
                results.append(dislog(f, p, ct))
    pt = crt(results, factors)
    # Китайская теорема об остатках
    print(pt)
    print(long_to_bytes(pt))
    # мэйн функция с выводом результата


if name == '__main__':
    main()
