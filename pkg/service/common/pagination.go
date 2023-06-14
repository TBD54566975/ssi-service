package common

type Page struct {
	// A storage dependent way of communicating the page to be retrieved. Empty string means the first page.
	Token string

	// A value of -1 means retrieval of all pages.
	Size int
}

func (page *Page) ToStorageArgs() (string, int) {
	token := ""
	if page != nil {
		token = page.Token
	}
	size := -1
	if page != nil {
		size = page.Size
	}
	return token, size
}
