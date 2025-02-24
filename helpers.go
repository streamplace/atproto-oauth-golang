package oauth

func tokenInSet(tok string, set []string) bool {
	for _, setTok := range set {
		if tok == setTok {
			return true
		}
	}

	return false
}
