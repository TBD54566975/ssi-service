package end2end

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func RunTest() error {
	fmt.Println("START")

	resp, err := http.Get("http://localhost:8080/readiness")

	body, err := ioutil.ReadAll(resp.Body)
	bodyString := string(body)

	fmt.Println(bodyString)

	return err
}
