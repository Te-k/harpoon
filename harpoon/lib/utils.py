
def unbracket(domain):
    """Remove protective bracket from a domain"""
    return domain.replace("[.]", ".")

def bracket(domain):
    """Add protective bracket to a domain"""
    last_dot = domain.rfind(".")
    return domain[:last_dot] + "[.]" + domain[last_dot+1:]
