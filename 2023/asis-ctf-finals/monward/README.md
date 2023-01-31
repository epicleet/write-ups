# Monward - AsisCTF Finals 2022

O AsisCTF é um grande CTF internacional que acontece todo ano, atualmente todos podem participar tanto do qualifier quanto da final. É considerado um CTF difícil e um dos mais famosos de acordo com a comunidade.

Esse desafio foi resolvido por 30 times de 357 no total. Eu considero ele de nível médio.

O desafio (arquivo chall.sage) dá pra gente 3 pontos (P, Q e R) numa curva elíptica e um valor enc que é um a mensagem multiplicada ao ponto P da curva. A função `monadd` representa a adição de dois pontos na curva, a função `monprod` multiplica um valor escalar a um ponto, a função `encrypt` faz a multiplicação da mensagem a um ponto e a função `monon` verifica se o ponto ta na curva.

A primeira coisa que devemos notar é que `enc` também é um ponto da curva, logo temos 4 pontos. A segunda coisa que devemos perceber é a equação da curva, na função `monon` de acordo com essa parte do código `(a*x**2 + y**2 - d*x**2*y**2) % p == 1` a função da curva é:

$$ax^2 + y^2 - dx^2y^2 = 1 \mod p$$

$$ax^2 + y^2 = 1 + dx^2y^2 \mod p$$

Então essa é uma [curva de edwards](https://en.wikipedia.org/wiki/Edwards_curve). Porém nós não temos os parâmetros da curva (a, d e p), logo temos que  descobrir esses valores primeiro. Se plugarmos cada ponto na equação vamos ter essas 4 equações:

$$
aP_x^2 + P_y^2 = 1 + dP_x^2P_y^2 \mod p
$$

$$
aQ_x^2 + Q_y^2 = 1 + dQ_x^2Q_y^2 \mod p
$$

$$
aR_x^2 + R_y^2 = 1 + dR_x^2R_y^2 \mod p
$$

$$
a*\text{enc}_x^2 + \text{enc}_y^2 = 1 + d*\text{enc}_x^2*\text{enc}_y^2 \mod p
$$

Isso são 4 equações e 3 icógnitas (a, d e p), o problema é que esse sistema é não linear, então pode ser que não seja "resolvível". Para saber se conseguimos resolver o sistema precisamos entender sobre [Ideais](https://pt.wikipedia.org/wiki/Ideal_(teoria_dos_an%C3%A9is)), [Base de Gröbner](https://pt.wikipedia.org/wiki/Base_de_Gr%C3%B6bner) e [variedades](https://pt.wikipedia.org/wiki/Variedade_alg%C3%A9brica). Isso são praticamente duas ou três disciplinas de algum curso de matemática numa universidade, ou um livro de geometria algébrica inteiro, então não dá para explicar todos esses conceitos aqui. Vamos apenas ver o que a base de groebner faz.

## Base de Groebner e Ideais

Vamos definir um ideal como um conjunto de elementos de um corpo que:
* Dado dois elementos a e b do conjunto, então a+b também está no conjunto.
* Dado um elemento a do conjunto e outro elemento h do anel polinomial multivariado do corpo base, então h*a também está no conjunto.

Ficou meio complicado né? Mas para gente só importa que o ideal vai ser uma lista dos polinômios...

A base de groebner é um conjunto gerador de um ideal, ou seja é como se fossem os elementos do ideal que só tendo eles já é possível gerar qualquer elemento. Isso é como se fosse a base que retiramos de um sistema linear quando rodamos eliminação gaussiana. Isso é útil para nós pois dessa forma conseguimos descobrir quais as icógnitas e resolver o nosso sistema multivariado.

## Achando as icógnitas

Bom, agora que entendemos bem pouco de ideais e base de groebner podemos usar o [sage](https://www.sagemath.org/) para achar a, d e p. Primeiro vamos criar nosso anel polinomial e montar os polinômios que chegamos acima:

```sage

P = (2021000018575600424643989294466413996315226194251212294606, 1252223168782323840703798006644565470165108973306594946199)
Q = (2022000008169923562059731170137238192288468444410384190235, 1132012353436889700891301544422979366627128596617741786134)
R = (2023000000389145225443427604298467227780725746649575053047, 4350519698064997829892841104596372491728241673444201615238)
enc = (3419907700515348009508526838135474618109130353320263810121, 5140401839412791595208783401208636786133882515387627726929)

PP.<a, d> = PolynomialRing(ZZ)

polys = []
x, y = P
polys.append((a*x**2 + y**2 - d*x**2*y**2) - 1)
x, y = Q
polys.append((a*x**2 + y**2 - d*x**2*y**2) - 1)
x, y = R
polys.append((a*x**2 + y**2 - d*x**2*y**2) - 1)
x, y = enc
polys.append((a*x**2 + y**2 - d*x**2*y**2) - 1)
```

Mas cadê o `p` aí? O `p` vai ser um zero do nosso ideal, então não precisamos dele como icógnita já que ele vai aparecer pois é um elemento da base. O que quero dizer é que todos os elementos vão ser um multiplo dele, então a nossa segunda regra da definição de ideal vai fazer ele aparecer na base.

Bom, como temos nossas equações na lista `polys` agora é só criar o ideal e rodar um algoritmo que acha a base de grobener do ideal:

```sage
I = PP.ideal(polys)
G = I.groebner_basis()
```

Rodando essa parte do código vamos encontrar:

```sage
[
    a + 110062003148225401725628246404818446720450976623225313995311,
    d + 154490734938099229849569067657352117192562308729750369601751, 
    209488070485061880311886074351169939903472896311680134404680
]
```

Sabe quando eu disse que o `p` vai ser um dos zeros do ideal? Eu menti, na verdade vai ser um múltiplo de `p`. O primeiro elemento da lista deu para a gente o valor de `a`, o segundo deu o valor de `d` e o terceiro um múltiplo de `p`. O que precisamos fazer agora é fatorar esse último elemento e encontrar o `p`, que provavelmente vai ser o maior primo da fatoração:

```sage
sage: factor(G[-1])
2^3 * 5 * 5237201762126547007797151858779248497586822407792003360117
# p = 5237201762126547007797151858779248497586822407792003360117
```

Bom, como encontramos o `p`agora é fácil achar `a` e `d` com as equações que achamos na base. Cada equação alí é igual a 0, então vai ficar assim:

$$
a + 110062003148225401725628246404818446720450976623225313995311 = 0 \mod p
$$

$$
a = -110062003148225401725628246404818446720450976623225313995311 \mod p
$$

$$
a = 5156435618558632445909094488325020226459116348198759927263 \mod p
$$

Só que no sage é muito mais fácil:

```sage
a = -(G[0].coefficients()[-1])%p
d = -(G[1].coefficients()[-1])%p
```

## Edwards -> Montgomery -> Weierstrass

Conseguimos descobrir os parâmetros da nossa curva elíptica! Porém tem um probleminha, ela está na forma de Edwards e não na de Weierstrass que é a que estamos acostumados. Uma coisa importante que precisamos saber é que os tipos de curva tem uma propriedade chamada birracional, essa propriedade garante que existe uma forma de transformar uma curva de um tipo para outro. Existe outra forma que envolve calcular o jacobiano da curva, mas aí vai complicar demais, melhor a gente usar os mapas de Edwards para Montgomery e depois de Montgomery para Weierstrass. Abaixo as equações de cada tipo de curva que vamos usar na conversão:

| Equação | Tipo        | Parâmetros |
|---------|-------------|------------|
| $y^2 = x^3 + ax + b \mod p$ | Weierstrass | a, b, p    |
| $By^2 = x^3 + Ax^2 + x \mod p$ | Montgomery  | B, A, p    |
| $ax^2 + y^2 = 1 + dx^2y^2 \mod p$ | Twisted Edwards     | a, d, p    |

Vamos definir o mapa de conversão de uma curva de Edwards para Montgomery como:

$$
E_e(a, d) \to E_m\Big(\frac{2(a+d)}{a-d}, \frac{4}{a-d}\\Big)
$$

Para um ponto P = (x, y) o mapa fica:

$$
(x, y) \mapsto \left(\frac{1 + y}{1 - y}, \frac{1 + y}{x - xy}\right)
$$

$$
(x, y)^{-1} \mapsto \left(\frac{x}{y}, \frac{x-1}{x+1}\right)
$$

Já os mapas de Montgomery para Weierstrass vai ficar assim:

$$
E_m(A, B) \to E_w\Big(\frac{1}{B^2} - \frac{A^2}{3B^2},\frac{A(2A^2-9)}{27B^3}\Big)
$$

$$
(x, y) \mapsto \Big(\frac{x + \frac{A}{3}}{B}, \frac{y}{B}\Big)
$$

$$
(x, y)^{-1} \mapsto \Big(xB - \frac{A}{3}, yB\Big)
$$

Os códigos de conversão de pontos e da curva ficam assim:

```sage
def Curve_EdwardsToMontgomery(p, a, d):
        A = (2*(a+d)*inverse(a-d, p))%p
        B = (4*inverse(a-d, p))%p
        return A, B

def Curve_EdwardsToWeierstrass(p, a, d):
        A, B = Curve_EdwardsToMontgomery(p, a, d)
        a = (1*inverse(B*B, p) - (A*A)*inverse(3*B*B,p))%p
        b = (A*(2*A**2 - 9)*inverse(27*B**3, p))%p
        return a, b


def Point_EdwardsToWeierstrass(p, a, d, P):
        x, y = P
        A, B = Curve_EdwardsToMontgomery(p, a, d)

        Px = ((1+y)*inverse(1-y, p))%p
        Py = ((1+y)*inverse(x-x*y, p))%p

        Pxx = ((Px + A*inverse(3, p))*inverse(B, p))%p
        Pyy = (Py*inverse(B, p))%p
        return E((Pxx, Pyy))


Wa, Wb = Curve_EdwardsToWeierstrass(p, a, d)

# Criamos a curva elliptica na forma de Weierstrass
E = EllipticCurve(GF(p), [Wa, Wb])

P = Point_EdwardsToWeierstrass(p, a, d, P)
enc = Point_EdwardsToWeierstrass(p, a, d, enc)
```

Para escrever o código que faz as conversões, eu usei essa referência do [stackexchange](https://crypto.stackexchange.com/questions/27842/edwards-montgomery-ecc-with-weierstrass-implementation). Para entender e ver as contas matemáticas por trás, precisamos ler [um artigo](https://eprint.iacr.org/2008/013) que meio que da um overview sobre as curvas de Edwards para uso em criptografia.

## Log discreto

Chegamos ao fim, precisamos descobrir qual o m que ta multiplicando o ponto P, já fizemos a conversão da curva de Edwards para Weierstrass e para descobrir esse m precisamos resolver um problema computacionalmente difícil, basicamente os esquemas de encrypt e assinatura usam ele como trapdoor. O problema do logaritimo discreto para curvas elípticas consiste em encontrar `m` dado `P` e `mP`, para algumas curvas conseguimos resolver ele rápido.

A curva do desafio foi criada sem pensar nas premissas de segurança, e acabou que os parâmetros escolhidos para ela ficaram vulneráveis, nesse caso específico a ordem da curva é um número facilmente fatorável. A ordem de uma curva elíptica é a quantidade de pontos/elementos no grupo dessa curva. Quando conseguimos fatorar a ordem facilmente, o problema do logaritmo discreto se reduz a resolver ele para cada primo que compõe a fatoração, e no final usamos o teorema chinês do resto para recuperar o valor do log discreto verdadeiro. O nome desse algoritmo é Pohlig-Hellman e o de resolver cada instância do log discreto podemos usar um chamado baby-step giant-step.

Por sorte o sage já implementa esse algoritmo, então a gente só precisa chamar a função `discret_log`:

```sage
print(long_to_bytes(int(discrete_log(enc,P,P.order(),operation='+'))))
```

Pronto, isso vai imprimir a flag para gente!