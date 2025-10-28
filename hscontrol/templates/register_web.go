package templates

import (
	"fmt"

	"github.com/chasefleming/elem-go"
	"github.com/juanfont/headscale/hscontrol/types"
)

func RegisterWeb(registrationID types.RegistrationID) *elem.Element {
	return HtmlStructure(
		elem.Title(nil, elem.Text("Registration - Headscale")),
		mdTypesetBody(
			headscaleLogo(),
			H1(elem.Text("Machine registration")),
			P(elem.Text("Run the command below in the headscale server to add this machine to your network:")),
			Pre(PreCode(fmt.Sprintf("headscale nodes register --key %s --user USERNAME", registrationID.String()))),
			pageFooter(),
		),
	)
}
