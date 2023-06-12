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

func ParsePaginationParams(c *gin.Context, pageRequest *PageRequest) bool {
	pageSizeStr := framework.GetParam(c, PageSizeParam)

	if pageSizeStr != nil {
		pageSize, err := strconv.Atoi(*pageSizeStr)
		if err != nil {
			errMsg := fmt.Sprintf("list DIDs by method request encountered a problem with the %q query param", PageSizeParam)
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

		query := PageTokenQuery(c)
		if !reflect.DeepEqual(pageTokenValues, query) {
			logrus.Warnf("expected query from token to be equal to query from request. token: %v\nrequest%v", pageTokenValues, query)
			framework.LoggingRespondErrMsg(c, "page token must be for the same query", http.StatusBadRequest)
			return true
		}
		pageRequest.PageToken = &pageToken.NextPageToken
	}
	return false
}

func PageTokenQuery(c *gin.Context) url.Values {
	query := c.Request.URL.Query()
	delete(query, PageTokenParam)
	delete(query, PageSizeParam)
	return query
}

func MaybeSetNextPageToken(c *gin.Context, serviceNextPageToken string, respNextPageToken *string) bool {
	if serviceNextPageToken != "" {
		tokenQuery := PageTokenQuery(c)
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

type PageRequest struct {
	// When nil, all DIDs will be returned.
	PageSize  *int    `json:"pageSize,omitempty"`
	PageToken *string `json:"pageToken,omitempty"`
}

func (r *PageRequest) ToServicePage() common.Page {
	const allPages = -1
	page := common.Page{Size: new(int)}
	*page.Size = allPages
	if r == nil {
		return page
	}

	if r != nil && r.PageSize != nil {
		page = common.Page{
			Token: r.PageToken,
			Size:  r.PageSize,
		}
	}
	return page
}
