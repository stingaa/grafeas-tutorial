// Copyright 2017 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"k8s.io/api/admission/v1alpha1"
	"net/http"
	"crypto/tls"
	"io/ioutil"
	"net/url"
)

var (
	grafeasUrl  string
	grafeasUser  string
	grafeasPassword  string
	filter  string
	tlsCertFile string
	tlsKeyFile  string
)

var (
	notesPath       = "/v1alpha1/projects/image-signing/notes"
	occurrencesPath = "/v1alpha1/projects/image-signing/occurrences"
)

func main() {
	grafeasUrl = os.Getenv("GRAFEAS_SERVER_URL")
	filter = os.Getenv("GRAFEAS_FILTER")
	grafeasUser = os.Getenv("GRAFEAS_USER")
	grafeasPassword = os.Getenv("GRAFEAS_PASSWORD")
	if grafeasUrl == "" {
		flag.StringVar(&grafeasUrl, "grafeas", "http://grafeas:8080", "The Grafeas server address")
	}
	if grafeasUser == "" {
		flag.StringVar(&grafeasUser, "grafeasUser", "", "The Grafeas username")
	}
	if grafeasPassword == "" {
		flag.StringVar(&grafeasPassword, "grafeasPassword", "", "The Grafeas password")
	}
	if filter == "" {
		flag.StringVar(&filter, "filter", "", "Grafeas filter expression")
	}

	flag.StringVar(&tlsCertFile, "tls-cert", "/etc/admission-controller/tls/cert.pem", "TLS certificate file.")
	flag.StringVar(&tlsKeyFile, "tls-key", "/etc/admission-controller/tls/key.pem", "TLS key file.")
	flag.Parse()

	log.Println(fmt.Sprintf("Grafeas server URL: %s", grafeasUrl))

	http.HandleFunc("/", admissionReviewHandler)
	s := http.Server{
		Addr: ":443",
		TLSConfig: &tls.Config{
			ClientAuth: tls.NoClientCert,
		},
	}
	log.Fatal(s.ListenAndServeTLS(tlsCertFile, tlsKeyFile))

}

func admissionReviewHandler(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	admissionReviewStatus := v1alpha1.AdmissionReviewStatus{Allowed: true}

	urlString := fmt.Sprintf("%s%s", grafeasUrl, occurrencesPath)
	u, err := url.Parse(urlString)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if filter != "" {
		parameters := url.Values{}
		parameters.Add("filter", filter)
		u.RawQuery = parameters.Encode()
	}
	urlString = u.String()
	log.Println(fmt.Sprintf("Sending request to grafeas: %s", urlString))

	client := &http.Client{}
	req, err := http.NewRequest("GET", urlString, nil)
	req.Header.Set("Content-Type", "application/json")
	if grafeasUser != "" {
		req.SetBasicAuth(grafeasUser, grafeasPassword)
	}
	resp, err := client.Do(req)

	occurances := make([]Occurance, 0)

	if err != nil {
		log.Println(err)
		goto done
	}

	data, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		resp.Body.Close()
		goto done
	}

	log.Println(fmt.Sprintf("Received response from grafeas: %s", string(data)))

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("non 200 status code: %d", resp.StatusCode)
		goto done
	}

	err = json.Unmarshal(data, &occurances)
	if err != nil {
		log.Println(err)
		goto done
	}

	log.Printf(fmt.Sprintf("Found %d occurances", len(occurances)))
	for i, occurance := range occurances {
		data, err = json.Marshal(occurance)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		log.Printf(fmt.Sprintf("%d. %s", i+1, string(data)))

		totalIssues := len(occurance.VulnerabilityDetails.PackageIssue)
		if totalIssues > 0 {
			admissionReviewStatus.Allowed = false
		}
	}

	goto done

done:
	data, err = json.Marshal(admissionReviewStatus)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Println(string(data))

	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

type Occurance struct {
	VulnerabilityDetails VulnerabilityDetails
}

type VulnerabilityDetails struct {
	PackageIssue []PackageIssue
}

type PackageIssue struct {
	SeverityName string
	AffectedLocation AffectedLocation
}

type AffectedLocation struct {
	Package string
	Version Version
}

type Version struct {
	name string
}

