package scanner

import (
	"fmt"

	"github.com/liamg/loading/pkg/bar"
)

type multibar struct {
	rootBar        *bar.Bar
	serviceBar     *bar.Bar
	currentService string
	serviceTotal   int
	serviceCurrent int
}

func newMultibar() *multibar {
	return &multibar{
		//rootBar: bar.New(
		//	bar.OptionWithLabel("Starting AWS scan..."),
		//	bar.OptionWithoutStatsFuncs(),
		//),
		serviceBar: bar.New(
			bar.OptionWithAutoComplete(false),
		),
	}
}

func (m *multibar) IncrementResource() {
	m.serviceBar.Increment()
}

func (m *multibar) SetTotalResources(i int) {
	m.serviceBar.SetTotal(i)
}

func (m *multibar) SetTotalServices(i int) {
	//m.rootBar.SetTotal(i)
	m.serviceTotal = i
}

func (m *multibar) SetServiceLabel(label string) {
	m.serviceBar.SetLabel("└╴" + label)
}

func (m *multibar) FinishService() {
	//m.rootBar.Log("Finished scanning %s.", m.currentService)
	//m.rootBar.Increment()
	m.serviceCurrent++
}

func (m *multibar) StartService(name string) {
	fmt.Printf("Scanning %s...\n", name)
	//m.rootBar.SetLabel(fmt.Sprintf("Scanning service %d of %d: %s...", m.serviceCurrent+1, m.serviceTotal, name))
	m.serviceBar.SetTotal(0)
	m.serviceBar.SetCurrent(0)
	m.serviceBar.SetLabel("Querying resources...")
	m.currentService = name
}
