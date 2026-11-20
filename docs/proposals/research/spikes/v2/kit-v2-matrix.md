| ID  | Class   | Input                                                       | cobra   | urfave  | kong    | creachadair | own-grammar | own-pflag |
| --- | ------- | ----------------------------------------------------------- | ------- | ------- | ------- | ----------- | ----------- | --------- |
| F05 | STRETCH | `headscale nodes list -ojson`                               | **F**   | P       | P       | P           | P           | P         |
| F28 | STRETCH | `headscale nodes list -ho json`                             | **F**   | P       | **F**→P | P           | P           | P         |
| B05 | MUST    | `headscale nodes delete 12 --force --force`                 | P       | P       | P       | P           | P           | P         |
| G11 | MUST    | `headscale -c /a nodes list -c /b`                          | P       | P       | P       | P           | P           | P         |
| D01 | MUST    | `headscale nodes delete 12 -- --force`                      | P       | P       | P       | P           | P           | P         |
| D02 | MUST    | `headscale nodes routes set 12 -- -o`                       | P       | P       | P       | P           | P           | P         |
| D03 | MUST    | `headscale nodes routes set 12 -- -h`                       | P       | P       | P       | P           | P           | P         |
| D04 | MUST    | `headscale -c /x nodes routes set 12 -- --config`           | P       | P       | P       | P           | P           | P         |
| D05 | MUST    | `headscale nodes routes set 12 -- --`                       | P       | P       | P       | P           | P           | P         |
| D06 | MUST    | `headscale nodes routes set 12 10.0.0.0/8 --`               | P       | P       | P       | P           | P           | P         |
| D07 | MUST    | `headscale nodes list -- extra`                             | P       | P       | P       | P           | P           | P         |
| D08 | MUST    | `headscale auth keys create alice -- --tags x`              | P       | P       | P       | P           | P           | P         |
| A01 | MUST    | `headscale nodes delete 12 13 --force 14`                   | P       | P       | **F**→P | P           | P           | P         |
| A02 | MUST    | `headscale nodes routes set 12 10.0.0.0/8 -o json extra`    | P       | P       | P       | P           | P           | P         |
| A03 | MUST    | `headscale check config a -c /x b`                          | P       | P       | P       | P           | P           | P         |
| A04 | MUST    | `headscale nodes delete list`                               | P       | P       | P       | P           | P           | P         |
| A05 | MUST    | `headscale users delete nodes`                              | P       | P       | P       | P           | P           | P         |
| R01 | MUST    | `headscale nodes list -o json -o yaml`                      | P       | P       | P       | P           | P           | P         |
| R02 | MUST    | `headscale -o json nodes list -o yaml`                      | P       | P       | P       | P           | P           | P         |
| R03 | MUST    | `headscale nodes list -o json --output yaml`                | P       | P       | P       | P           | P           | P         |
| R04 | MUST    | `headscale nodes delete 12 --force=true --force`            | P       | P       | P       | P           | P           | P         |
| R05 | MUST    | `headscale nodes set 12 --name a --name ''`                 | P       | P       | P       | P           | P           | P         |
| R06 | MUST    | `headscale --config=/a -c /b version`                       | P       | P       | P       | P           | P           | P         |
| G12 | MUST    | `headscale -c nodes nodes list`                             | P       | P       | P       | P           | P           | P         |
| G13 | MUST    | `headscale -o=json nodes list`                              | P       | P       | P       | P           | P           | P         |
| G14 | MUST    | `headscale -c=/x nodes list`                                | P       | P       | P       | P           | P           | P         |
| G15 | MUST    | `headscale -c '' nodes list`                                | P       | P       | P       | P           | P           | P         |
| X01 | STRETCH | `headscale auth keys create alice -e24h`                    | **F**   | P       | P       | P           | P           | P         |
| X02 | STRETCH | `headscale nodes list -output json`                         | **F**   | **F**   | P       | **F**       | P           | P         |
| X03 | STRETCH | `headscale nodes list --o json`                             | P       | **F**   | P       | **F**       | P           | P         |
| O01 | OBSERVE | `headscale nodes set 12 --name -h`                          | ·       | ·       | ·       | ·           | ·           | ·         |
| O02 | OBSERVE | `headscale nodes set 12 --name --`                          | ·       | ·       | ·       | ·           | ·           | ·         |
| O03 | OBSERVE | `headscale nodes -c /x list`                                | ·       | ·       | ·       | ·           | ·           | ·         |
| O04 | OBSERVE | `headscale nodes --force delete 12`                         | ·       | ·       | ·       | ·           | ·           | ·         |
| O05 | OBSERVE | `headscale nodes list --help=false`                         | ·       | ·       | ·       | ·           | ·           | ·         |
| N01 | MUST    | `headscale nodes ''<TAB>`                                   | **F**→P | **F**→P | **F**→P | **F**→P     | P           | P         |
| N02 | MUST    | `headscale nodes l<TAB>`                                    | **F**→P | **F**→P | **F**→P | **F**→P     | P           | P         |
| N03 | MUST    | `headscale nodes r<TAB>`                                    | **F**→P | **F**→P | **F**→P | **F**→P     | P           | P         |
| N04 | MUST    | `headscale users ''<TAB>`                                   | **F**→P | **F**→P | **F**→P | **F**→P     | P           | P         |
| N05 | MUST    | `headscale nodes routes ''<TAB>`                            | **F**→P | **F**→P | **F**→P | **F**→P     | P           | P         |
| N06 | MUST    | `headscale -c /x nodes l<TAB>`                              | **F**→P | **F**→P | **F**→P | **F**→P     | P           | P         |
| N07 | MUST    | `headscale nodes rm 12 --f<TAB>`                            | P       | P       | P       | P           | P           | P         |
| N08 | MUST    | `headscale nodes delete ''<TAB>`                            | P       | **F**→P | P       | P           | P           | P         |
| N09 | MUST    | `headscale nodes list ''<TAB>`                              | P       | **F**→P | P       | P           | P           | P         |
| N10 | MUST    | `headscale completion ''<TAB>`                              | P       | P       | P       | P           | P           | P         |
| N11 | MUST    | `headscale nodes delete 12 ''<TAB>`                         | P       | **F**→P | P       | P           | P           | P         |
| N12 | MUST    | `headscale check config -c /x ''<TAB>`                      | P       | P       | P       | P           | P           | P         |
| N13 | MUST    | `headscale -c /x check config ''<TAB>`                      | P       | P       | P       | P           | P           | P         |
| N14 | MUST    | `headscale policy set --dry-run ''<TAB>`                    | P       | P       | P       | P           | P           | P         |
| N15 | MUST    | `headscale check config --<TAB>`                            | P       | P       | P       | P           | P           | P         |
| N16 | MUST    | `headscale completion --<TAB>`                              | P       | P       | P       | P           | P           | P         |
| N17 | MUST    | `headscale serve --<TAB>`                                   | P       | P       | P       | P           | P           | P         |
| N18 | MUST    | `headscale -o ''<TAB>`                                      | **F**→P | P       | P       | P           | P           | P         |
| N19 | STRETCH | `headscale auth keys create alice --tags tag:p<TAB>`        | P       | **F**→P | P       | P           | P           | P         |
| N20 | STRETCH | `headscale auth keys create alice --tags tag:ci,tag:p<TAB>` | P       | **F**→P | P       | P           | P           | P         |
| N21 | STRETCH | `headscale nodes routes set 12 -- --<TAB>`                  | P       | P→**F** | **F**→P | P           | **F**→P     | **F**→P   |
