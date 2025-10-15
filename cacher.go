package entraptor

/*
Cacher is an interface for allowing the user of the library to roll their own caching solution.
By default a DummyCacher is used which does nothing.
*/
type Cacher interface {
	Get(string) ([]string, bool, error)
	Set(string, []string) error
	CacheKey(string) string
}

type DummyCacher struct {
}

func (d DummyCacher) Get(key string) ([]string, bool, error) {
	return nil, false, nil
}

func (d DummyCacher) Set(key string, value []string) error {
	return nil
}

func (d DummyCacher) CacheKey(token string) string {
	return token
}
