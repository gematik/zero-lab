package epa

import (
	"fmt"
	"net/http"
)

func (c *Client) GetRecordStatus(insurantId string) (bool, error) {

	// set insurantId as header
	req, err := http.NewRequest("GET", c.urlAS+"/information/api/v1/ehr", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-insurantid", insurantId)

	// send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}

	if resp.StatusCode == http.StatusNoContent {
		return true, nil
	} else if resp.StatusCode == http.StatusNotFound {
		return false, nil
	} else {
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

}
