import re

def linearize_anf(expr):
    terms = [t.strip() for t in expr.split('+')]
    
    linear_terms = []
    mapping = {}

    for term in terms:
        if term == "1":
            linear_terms.append("1")
            continue
        
        vars_ = re.findall(r"s_\d+", term)
        
        if len(vars_) == 1:
            linear_terms.append(vars_[0])
        else:
            key = tuple(sorted(vars_))
            
            if key not in mapping:
                name = "m_" + "_".join(v.split('_')[1] for v in key)
                mapping[key] = name
                
            linear_terms.append(mapping[key])
    
    linear_expr = " + ".join(linear_terms)
    
    return linear_expr, mapping


expr = """s_46 * s_21 + s_7 + s_1 * s_7 + s_46 * s_7 + s_1 * s_21 * s_7 + s_46 * s_21 * s_7 + s_43 + s_1 * s_43 + s_46 * s_43 + s_1 * s_21 * s_43 + s_1 * s_7 * s_43 + s_1 * s_21 * s_7 * s_43 + s_1 * s_46 * s_21 * s_7 * s_43 + s_0 + s_1 * s_0 + s_21 * s_0 + s_1 * s_46 * s_21 * s_0 + s_7 * s_0 + s_1 * s_46 * s_7 * s_0 + s_21 * s_43 * s_0 + s_1 * s_21 * s_43 * s_0 + s_46 * s_21 * s_43 * s_0 + s_1 * s_46 * s_21 * s_43 * s_0 + s_7 * s_43 * s_0 + s_1 * s_46 * s_7 * s_43 * s_0 + s_1 * s_46 * s_21 * s_7 * s_43 * s_0 + s_27 + s_46 * s_27 + s_1 * s_46 * s_27 + s_46 * s_21 * s_27 + s_7 * s_27 + s_46 * s_7 * s_27 + s_1 * s_21 * s_7 * s_27 + s_46 * s_21 * s_7 * s_27 + s_43 * s_27 + s_1 * s_46 * s_43 * s_27 + s_1 * s_21 * s_43 * s_27 + s_46 * s_21 * s_43 * s_27 + s_1 * s_46 * s_21 * s_43 * s_27 + s_7 * s_43 * s_27 + s_1 * s_46 * s_7 * s_43 * s_27 + s_21 * s_7 * s_43 * s_27 + s_1 * s_46 * s_21 * s_7 * s_43 * s_27 + s_46 * s_0 * s_27 + s_1 * s_46 * s_0 * s_27 + s_21 * s_0 * s_27 + s_1 * s_46 * s_21 * s_0 * s_27 + s_21 * s_7 * s_0 * s_27 + s_1 * s_21 * s_7 * s_0 * s_27 + s_46 * s_21 * s_7 * s_0 * s_27 + s_1 * s_43 * s_0 * s_27 + s_46 * s_43 * s_0 * s_27 + s_46 * s_7 * s_43 * s_0 * s_27 + s_1 * s_46 * s_7 * s_43 * s_0 * s_27 + s_21 * s_7 * s_43 * s_0 * s_27 + s_1 * s_21 * s_7 * s_43 * s_0 * s_27 + s_46 * s_21 * s_7 * s_43 * s_0 * s_27 + s_39 + s_1 * s_46 * s_39 + s_21 * s_39 + s_1 * s_21 * s_39 + s_46 * s_21 * s_39 + s_1 * s_46 * s_7 * s_39 + s_21 * s_7 * s_39 + s_43 * s_39 + s_21 * s_43 * s_39 + s_1 * s_46 * s_21 * s_43 * s_39 + s_1 * s_7 * s_43 * s_39 + s_46 * s_7 * s_43 * s_39 + s_1 * s_46 * s_7 * s_43 * s_39 + s_21 * s_7 * s_43 * s_39 + s_1 * s_21 * s_7 * s_43 * s_39 + s_46 * s_21 * s_7 * s_43 * s_39 + s_0 * s_39 + s_1 * s_0 * s_39 + s_1 * s_21 * s_0 * s_39 + s_46 * s_21 * s_0 * s_39 + s_46 * s_7 * s_0 * s_39 + s_1 * s_46 * s_7 * s_0 * s_39 + s_46 * s_21 * s_7 * s_0 * s_39 + s_1 * s_46 * s_21 * s_7 * s_0 * s_39 + s_1 * s_43 * s_0 * s_39 + s_46 * s_43 * s_0 * s_39 + s_46 * s_21 * s_43 * s_0 * s_39 + s_1 * s_46 * s_21 * s_43 * s_0 * s_39 + s_7 * s_43 * s_0 * s_39 + s_46 * s_7 * s_43 * s_0 * s_39 + s_1 * s_46 * s_7 * s_43 * s_0 * s_39 + s_21 * s_27 * s_39 + s_1 * s_21 * s_27 * s_39 + s_1 * s_46 * s_21 * s_27 * s_39 + s_7 * s_27 * s_39 + s_1 * s_46 * s_7 * s_27 * s_39 + s_46 * s_21 * s_7 * s_27 * s_39 + s_1 * s_46 * s_21 * s_7 * s_27 * s_39 + s_43 * s_27 * s_39 + s_1 * s_43 * s_27 * s_39 + s_46 * s_43 * s_27 * s_39 + s_1 * s_46 * s_43 * s_27 * s_39 + s_21 * s_43 * s_27 * s_39 + s_1 * s_21 * s_43 * s_27 * s_39 + s_1 * s_7 * s_43 * s_27 * s_39 + s_46 * s_7 * s_43 * s_27 * s_39 + s_1 * s_46 * s_7 * s_43 * s_27 * s_39 + s_21 * s_7 * s_43 * s_27 * s_39 + s_46 * s_21 * s_7 * s_43 * s_27 * s_39 + s_0 * s_27 * s_39 + s_46 * s_0 * s_27 * s_39 + s_1 * s_21 * s_0 * s_27 * s_39 + s_46 * s_7 * s_0 * s_27 * s_39 + s_1 * s_46 * s_7 * s_0 * s_27 * s_39 + s_1 * s_21 * s_7 * s_0 * s_27 * s_39 + s_1 * s_46 * s_21 * s_7 * s_0 * s_27 * s_39 + s_1 * s_43 * s_0 * s_27 * s_39 + s_46 * s_43 * s_0 * s_27 * s_39 + s_1 * s_46 * s_43 * s_0 * s_27 * s_39 + s_46 * s_7 * s_43 * s_0 * s_27 * s_39 + s_46 * s_21 * s_7 * s_43 * s_0 * s_27 * s_39"""

lin_expr, mapping = linearize_anf(expr)

print("Linearized equation:")
print(lin_expr)

print("\nVariable mapping:")
for k,v in mapping.items():
    print(v,"=", "*".join(k))

print(len(mapping), "new variables introduced.")