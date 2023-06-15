package pagination

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/common"
)

type PageToken struct {
	EncodedQuery  string
	NextPageToken string
}

const (
	PageSizeParam  = "pageSize"
	PageTokenParam = "pageToken"
)

// ParsePaginationParams reads the PageSizeParam and PageTokenParam from the URL parameters and populates the passed in
// pageRequest. The value encoded in PageTokenParam is assumed to be the base64url encoding of a PageToken. It is an
// error for the query params to be different from the query params encoded in the PageToken. Any error during the
// execution is responded to using the passed in gin.Context. The return value corresponds to whether there was an
// error within the function.
func ParsePaginationParams(c *gin.Context, pageRequest *PageRequest) bool {
	pageSizeStr := framework.GetParam(c, PageSizeParam)

	if pageSizeStr != nil {
		pageSize, err := strconv.Atoi(*pageSizeStr)
		if err != nil {
			errMsg := fmt.Sprintf("list DIDs by method request encountered a problem with the %q query param", PageSizeParam)
			framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
			return true
		}
		if pageSize <= 0 {
			errMsg := fmt.Sprintf("'%s' must be greater than 0", PageSizeParam)
			framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
			return true
		}
		pageRequest.PageSize = &pageSize
	}

	queryPageToken := framework.GetParam(c, PageTokenParam)
	if queryPageToken != nil {
		errMsg := "token value cannot be decoded"
		tokenData, err := base64.RawURLEncoding.DecodeString(*queryPageToken)
		if err != nil {
			framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
			return true
		}
		var pageToken PageToken
		if err := json.Unmarshal(tokenData, &pageToken); err != nil {
			framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
			return true
		}
		pageTokenValues, err := url.ParseQuery(pageToken.EncodedQuery)
		if err != nil {
			framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
			return true
		}

		query := pageTokenQuery(c)
		if !reflect.DeepEqual(pageTokenValues, query) {
			logrus.Warnf("expected query from token to be equal to query from request. token: %v\nrequest%v", pageTokenValues, query)
			framework.LoggingRespondErrMsg(c, "page token must be for the same query", http.StatusBadRequest)
			return true
		}
		pageRequest.PageToken = &pageToken.NextPageToken
	}
	return false
}

func pageTokenQuery(c *gin.Context) url.Values {
	query := c.Request.URL.Query()
	delete(query, PageTokenParam)
	delete(query, PageSizeParam)
	return query
}

// MaybeSetNextPageToken encodes the serviceNextPageToken and the URL query params into a base64url string. The encoded
// string is assigned to what respNextPageToken is pointing to. respNextPageToken cannot be nil. Any error during the
// execution is responded to using the passed in gin.Context. The return value corresponds to whether there was an error
// within the function.
func MaybeSetNextPageToken(c *gin.Context, serviceNextPageToken string, respNextPageToken *string) bool {
	if serviceNextPageToken != "" {
		tokenQuery := pageTokenQuery(c)
		pageToken := PageToken{
			EncodedQuery:  tokenQuery.Encode(),
			NextPageToken: serviceNextPageToken,
		}
		nextPageTokenData, err := json.Marshal(pageToken)
		if err != nil {
			framework.LoggingRespondErrWithMsg(c, err, "marshalling page token", http.StatusInternalServerError)
			return true
		}
		encodedToken := base64.RawURLEncoding.EncodeToString(nextPageTokenData)
		*respNextPageToken = encodedToken
	}
	return false
}

// PageRequest contains the parameters sent in the request.
type PageRequest struct {
	// PageSize is the value associated with PageSizeParam. A nil value means it was not present in the query. When the parameter
	// is absent, all items in the collection are included in the response.
	PageSize *int `json:"pageSize,omitempty"`

	// PageToken is the value associated with PageTokenParam. A nil value means it was not present in the query.
	PageToken *string `json:"pageToken,omitempty"`
}

func (r *PageRequest) ToServicePage() *common.Page {
	const allPages = -1
	page := common.Page{
		Size: allPages,
	}
	if r == nil {
		return &page
	}

	if r.PageSize != nil {
		page.Size = *r.PageSize
	}
	if r.PageToken != nil {
		page.Token = *r.PageToken
	}
	return &page
}
