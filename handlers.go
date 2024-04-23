package main

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/skupperproject/skupper/pkg/flow"
)

func (c *RestController) eventsourceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.FlowCollector.Request <- flow.ApiRequest{RecordType: flow.EventSource, Request: r}
	response := <-c.FlowCollector.Response
	w.WriteHeader(response.Status)
	if response.Body != nil {
		fmt.Fprintf(w, "%s", *response.Body)
	}
}

func (c *RestController) siteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.FlowCollector.Request <- flow.ApiRequest{RecordType: flow.Site, Request: r}
	response := <-c.FlowCollector.Response
	w.WriteHeader(response.Status)
	if response.Body != nil {
		fmt.Fprintf(w, "%s", *response.Body)
	}
}

func (c *RestController) hostHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.FlowCollector.Request <- flow.ApiRequest{RecordType: flow.Host, Request: r}
	response := <-c.FlowCollector.Response
	w.WriteHeader(response.Status)
	if response.Body != nil {
		fmt.Fprintf(w, "%s", *response.Body)
	}
}

func (c *RestController) routerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.FlowCollector.Request <- flow.ApiRequest{RecordType: flow.Router, Request: r}
	response := <-c.FlowCollector.Response
	w.WriteHeader(response.Status)
	if response.Body != nil {
		fmt.Fprintf(w, "%s", *response.Body)
	}
}

func (c *RestController) linkHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.FlowCollector.Request <- flow.ApiRequest{RecordType: flow.Link, Request: r}
	response := <-c.FlowCollector.Response
	w.WriteHeader(response.Status)
	if response.Body != nil {
		fmt.Fprintf(w, "%s", *response.Body)
	}
}

func (c *RestController) listenerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.FlowCollector.Request <- flow.ApiRequest{RecordType: flow.Listener, Request: r}
	response := <-c.FlowCollector.Response
	w.WriteHeader(response.Status)
	if response.Body != nil {
		fmt.Fprintf(w, "%s", *response.Body)
	}
}

func (c *RestController) connectorHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.FlowCollector.Request <- flow.ApiRequest{RecordType: flow.Connector, Request: r}
	response := <-c.FlowCollector.Response
	w.WriteHeader(response.Status)
	if response.Body != nil {
		fmt.Fprintf(w, "%s", *response.Body)
	}
}

func (c *RestController) addressHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.FlowCollector.Request <- flow.ApiRequest{RecordType: flow.Address, Request: r}
	response := <-c.FlowCollector.Response
	w.WriteHeader(response.Status)
	if response.Body != nil {
		fmt.Fprintf(w, "%s", *response.Body)
	}
}

func (c *RestController) processHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.FlowCollector.Request <- flow.ApiRequest{RecordType: flow.Process, Request: r}
	response := <-c.FlowCollector.Response
	w.WriteHeader(response.Status)
	if response.Body != nil {
		fmt.Fprintf(w, "%s", *response.Body)
	}
}

func (c *RestController) processGroupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.FlowCollector.Request <- flow.ApiRequest{RecordType: flow.ProcessGroup, Request: r}
	response := <-c.FlowCollector.Response
	w.WriteHeader(response.Status)
	if response.Body != nil {
		fmt.Fprintf(w, "%s", *response.Body)
	}
}

func (c *RestController) flowHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.FlowCollector.Request <- flow.ApiRequest{RecordType: flow.Flow, Request: r}
	response := <-c.FlowCollector.Response
	w.WriteHeader(response.Status)
	if response.Body != nil {
		fmt.Fprintf(w, "%s", *response.Body)
	}
}

func (c *RestController) flowPairHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.FlowCollector.Request <- flow.ApiRequest{RecordType: flow.FlowPair, Request: r}
	response := <-c.FlowCollector.Response
	w.WriteHeader(response.Status)
	if response.Body != nil {
		fmt.Fprintf(w, "%s", *response.Body)
	}
}

func (c *RestController) sitePairHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.FlowCollector.Request <- flow.ApiRequest{RecordType: flow.SitePair, Request: r}
	response := <-c.FlowCollector.Response
	w.WriteHeader(response.Status)
	if response.Body != nil {
		fmt.Fprintf(w, "%s", *response.Body)
	}
}

func (c *RestController) processGroupPairHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.FlowCollector.Request <- flow.ApiRequest{RecordType: flow.ProcessGroupPair, Request: r}
	response := <-c.FlowCollector.Response
	w.WriteHeader(response.Status)
	if response.Body != nil {
		fmt.Fprintf(w, "%s", *response.Body)
	}
}

func (c *RestController) processPairHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.FlowCollector.Request <- flow.ApiRequest{RecordType: flow.ProcessPair, Request: r}
	response := <-c.FlowCollector.Response
	w.WriteHeader(response.Status)
	if response.Body != nil {
		fmt.Fprintf(w, "%s", *response.Body)
	}
}

func (c *RestController) collectorHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c.FlowCollector.Request <- flow.ApiRequest{RecordType: flow.Collector, Request: r}
	response := <-c.FlowCollector.Response
	w.WriteHeader(response.Status)
	if response.Body != nil {
		fmt.Fprintf(w, "%s", *response.Body)
	}
}

func (c *RestController) promqueryHandler(w http.ResponseWriter, r *http.Request) {
	client := http.Client{}

	urlOut := c.FlowCollector.Collector.PrometheusUrl + "query?" + r.URL.RawQuery
	proxyReq, err := http.NewRequest(r.Method, urlOut, nil)
	if err != nil {
		log.Printf("COLLECTOR: prom proxy request error: %s\n", err.Error())

		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Internal Server Error: %s\n", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	proxyResp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("COLLECTOR: Prometheus query error: %s\n", err.Error())

		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Internal Server Error: %s\n", err.Error())
		return
	} else {
		w.WriteHeader(proxyResp.StatusCode)
		data, _ := io.ReadAll(proxyResp.Body)
		proxyResp.Body.Close()
		fmt.Fprintf(w, "%s\n", data)
	}
}

func (c *RestController) promqueryrangeHandler(w http.ResponseWriter, r *http.Request) {
	client := http.Client{}

	urlOut := c.FlowCollector.Collector.PrometheusUrl + "query_range?" + r.URL.RawQuery
	proxyReq, err := http.NewRequest(r.Method, urlOut, nil)
	if err != nil {
		log.Printf("COLLECTOR: prom proxy request error: %s \n", err.Error())

		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Internal Server Error: %s\n", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	proxyResp, err := client.Do(proxyReq)
	w.WriteHeader(proxyResp.StatusCode)
	if err != nil {
		log.Printf("COLLECTOR: Prometheus query_range error: %s\n", err.Error())

		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Internal Server Error: %s\n", err.Error())
		return
	} else {
		data, _ := io.ReadAll(proxyResp.Body)
		proxyResp.Body.Close()
		fmt.Fprintf(w, "%s\n", data)
	}
}
