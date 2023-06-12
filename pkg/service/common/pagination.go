package common

type Page struct {
	Token *string
	Size  *int
}

func (page *Page) ToStorageArgs() (string, int) {
	token := ""
	if page != nil && page.Token != nil {
		token = *page.Token
	}
	size := -1
	if page != nil && page.Size != nil {
		size = *page.Size
	}
	return token, size
}
