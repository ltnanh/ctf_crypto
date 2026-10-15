

from sympy import factorint

def factorize_p1(p, limit=10**7):
    p1 = p - 1
    factors = factorint(p1)
    
    small_factors = {k: v for k, v in factors.items() if k < limit}
    
    remaining = p1
    for k, v in small_factors.items():
        remaining //= (k ** v)
    
    return small_factors, remaining

p= 200167626629249973590210748210664315551571227173732968065685194568612605520816305417784745648399324178485097581867501503778073506528170960879344249321872139638179291829086442429009723480288604047975360660822750743411854623254328369265079475034447044479229192540942687284442586906047953374527204596869578972378578818243592790149118451253249
factor = factorize_p1(p)

for num in factor[0]:
    if factor[0][num] == 1:
        print(num,end = " * ")
    else:
        print(f"{num}^{factor[0][num]}",end = " * ")

print(factor[1]) 
    


