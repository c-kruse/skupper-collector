package main

import (
	"log"
	"time"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/skupperproject/skupper/pkg/qdr"
)

type RestController struct {
	FlowCollector *FlowCollector
}

func NewController(origin string, reg prometheus.Registerer, scheme string, host string, port string, tlsConfig qdr.TlsConfigRetriever, recordTtl time.Duration) (*RestController, error) {

	controller := &RestController{
		FlowCollector: NewFlowCollector(FlowCollectorSpec{
			Mode:              RecordMetrics,
			Origin:            origin,
			PromReg:           reg,
			ConnectionFactory: qdr.NewConnectionFactory(scheme+"://"+host+":"+port, tlsConfig),
			FlowRecordTtl:     recordTtl,
		}),
	}

	return controller, nil
}

func (c *RestController) Run(stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()

	log.Println("COLLECTOR: Starting the Skupper flow collector")

	c.FlowCollector.Start(stopCh)

	<-stopCh
	log.Println("COLLECTOR: Shutting down the Skupper flow collector")

	return nil
}
