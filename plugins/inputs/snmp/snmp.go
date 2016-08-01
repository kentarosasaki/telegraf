package snmp

import (
	"fmt"
	"math"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/plugins/inputs"

	"github.com/soniah/gosnmp"
)

const description = `Retrieves SNMP values from remote agents`
const sampleConfig = `
  agents = ["127.0.0.1:161"]
  version = 2 # Values: 1, 2, or 3

  ## SNMPv1 & SNMPv2 parameters
  community = "public"

  ## SNMPv2 & SNMPv3 parameters
  max_repetitions = 50

  ## SNMPv3 parameters
  #sec_name = "myuser"
  #auth_protocol = "md5"         # Values: "MD5", "SHA", ""
  #auth_password = "password123"
  #sec_level = "authNoPriv"      # Values: "noAuthNoPriv", "authNoPriv", "authPriv"
  #context_name = ""
  #priv_protocol = ""            # Values: "DES", "AES", ""
  #priv_password = ""

  ## Each 'tag' is an "snmpget" request. Tags are inherited by snmp walk
  ## and get requests specified below. If a name for the tag is not provided,
  ## we will attempt to use snmptranslate on the OID to get the MIB name.
  [[inputs.snmp.tag]]
    name = "hostname" # optional, tag name
    oid = ".1.2.3.0.1.1"
  [[inputs.snmp.tag]]
    name = "datacenter"
    oid = ".1.3.6.1.2.1.1.6.0"

  ## Each 'get' is an "snmpget" request. If a name for the field is not provided,
  ## we will attempt to use snmptranslate on the OID to get the MIB name.
  [[inputs.snmp.get]]
    name = "hostname" # optional, field name
    oid = ".1.2.3.0.1.1"
  [[inputs.snmp.get]]
    oid = ".1.2.3.0.1.201"

  ## An SNMP walk will do an "snmpwalk" from the given root OID.
  ## Each OID it encounters will be converted into a field on the measurement.
  ## We will attempt to use snmptranslate on the OID to get the MIB names for
  ## each field.
  [[inputs.snmp.walk]]
    inherit_tags = ["hostname"] # optional, specify which top-level tags to inherit
    name = "snmp_walk" # measurement name
    root_oid = ".1.3.6.1.2.1.11"
`

// Snmp holds the configuration for the plugin.
type Snmp struct {
	// The SNMP agent to query. Format is ADDR[:PORT] (e.g. 1.2.3.4:161).
	Agents []string
	// Timeout to wait for a response. Value is anything accepted by time.ParseDuration().
	Timeout string
	Retries int
	// Values: 1, 2, 3
	Version uint8

	// Parameters for Version 1 & 2
	Community string

	// Parameters for Version 2 & 3
	MaxRepetitions uint

	// Parameters for Version 3
	ContextName string
	// Values: "noAuthNoPriv", "authNoPriv", "authPriv"
	SecLevel string
	SecName  string
	// Values: "MD5", "SHA", "". Default: ""
	AuthProtocol string
	AuthPassword string
	// Values: "DES", "AES", "". Default: ""
	PrivProtocol string
	PrivPassword string

	// Name & Fields are the elements of a Table.
	// Telegraf chokes if we try to embed a Table. So instead we have to embed
	// the fields of a Table, and construct a Table during runtime.
	Name  string
	Gets  []Get  `toml:"get"`
	Walks []Walk `toml:"walk"`
	Tags  []Tag  `toml:"tag"`

	// oidToMib is a map of OIDs to MIBs.
	oidToMib map[string]string
	// translateBin is the location of the 'snmptranslate' binary.
	translateBin string

	connectionCache map[string]snmpConnection
}

// Get holds the configuration for a Get to look up.
type Get struct {
	// Name will be the name of the field.
	Name string
	// OID is prefix for this field.
	Oid string
	// Conversion controls any type conversion that is done on the value.
	//  "float"/"float(0)" will convert the value into a float.
	//  "float(X)" will convert the value into a float, and then move the decimal before Xth right-most digit.
	//  "int" will conver the value into an integer.
	Conversion string
}

// Walker holds the configuration for a Walker to look up.
type Walk struct {
	// Name will be the name of the measurement.
	Name string
	// OID is prefix for this field. The plugin will perform a walk through all
	// OIDs with this as their parent. For each value found, the plugin will strip
	// off the OID prefix, and use the remainder as the index. For multiple fields
	// to show up in the same row, they must share the same index.
	RootOid string
}

// Tag holds the config for a tag.
type Tag struct {
	// Name will be the name of the tag.
	Name string
	// OID is prefix for this field.
	Oid string
}

// SampleConfig returns the default configuration of the input.
func (s *Snmp) SampleConfig() string {
	return sampleConfig
}

// Description returns a one-sentence description on the input.
func (s *Snmp) Description() string {
	return description
}

// Gather retrieves all the configured fields and tables.
// Any error encountered does not halt the process. The errors are accumulated
// and returned at the end.
func (s *Snmp) Gather(acc telegraf.Accumulator) error {
	for _, agent := range s.Agents {
		gs, err := s.getConnection(agent)
		if err != nil {
			acc.AddError(fmt.Errorf("Agent %s, err: %s", agent, err))
			continue
		}

		tags := map[string]string{}
		// Gather all snmp tags
		for _, t := range s.Tags {
			tagval, err := get(gs, t.Oid, "string")
			if err != nil {
				acc.AddError(fmt.Errorf("Agent %s, err: %s", agent, err))
				continue
			}
			if tagval == nil {
				continue
			}
			name := t.Name
			if name == "" {
				name = s.getMibName(t.Oid)
			}
			if s, ok := tagval.(string); ok {
				tags[name] = s
			}
		}

		// Gather all snmp gets
		fields := map[string]interface{}{}
		for _, g := range s.Gets {
			val, err := get(gs, g.Oid, g.Conversion)
			if err != nil {
				acc.AddError(fmt.Errorf("Agent %s, err: %s", agent, err))
				continue
			}
			if val == nil {
				continue
			}
			name := g.Name
			if name == "" {
				name = s.getMibName(g.Oid)
			}
			fields[name] = val
		}
		if len(fields) > 0 {
			acc.AddFields("snmp", fields, tags, time.Now())
		}

		// Gather all snmp walks
		for _, w := range s.Walks {
			wfields := map[string]interface{}{}
			s.walk(gs, wfields, w.RootOid)
			if len(wfields) > 0 {
				acc.AddFields(w.Name, wfields, copyTags(tags), time.Now())
			}
		}
	}

	return nil
}

// walk does a walk and populates the given 'fields' map with whatever it finds.
// as it goes, it attempts to lookup the MIB name of each OID it encounters.
func (s *Snmp) walk(
	gs snmpConnection,
	fields map[string]interface{},
	oid string,
) {
	gs.Walk(oid, func(ent gosnmp.SnmpPDU) error {
		name := s.getMibName(ent.Name)
		fields[name] = ent.Value
		return nil
	})
}

// get simply gets the given OID and converts it to the given type.
func get(gs snmpConnection, oid string, conv string) (interface{}, error) {
	pkt, err := gs.Get([]string{oid})
	if err != nil {
		return nil, fmt.Errorf("Error performing get: %s", err)
	}
	if pkt != nil && len(pkt.Variables) > 0 && pkt.Variables[0].Type != gosnmp.NoSuchObject {
		ent := pkt.Variables[0]
		return fieldConvert(conv, ent.Value), nil
	}
	return nil, nil
}

func (s *Snmp) getMibName(oid string) string {
	name, ok := s.oidToMib[oid]
	if !ok {
		// lookup the mib using snmptranslate
		name = lookupOidName(s.translateBin, oid)
		s.oidToMib[oid] = name
	}
	return name
}

// lookupOidName looks up the MIB name of the given OID using the provided
// snmptranslate binary. If a name is not found, then we just return the OID.
func lookupOidName(bin, oid string) string {
	name := oid
	if bin != "" {
		out, err := internal.CombinedOutputTimeout(
			exec.Command(bin, "-Os", oid),
			time.Millisecond*250)
		if err == nil && len(out) > 0 {
			name = strings.TrimSpace(string(out))
		}
	}
	return name
}

// snmpConnection is an interface which wraps a *gosnmp.GoSNMP object.
// We interact through an interface so we can mock it out in tests.
type snmpConnection interface {
	Host() string
	//BulkWalkAll(string) ([]gosnmp.SnmpPDU, error)
	Walk(string, gosnmp.WalkFunc) error
	Get(oids []string) (*gosnmp.SnmpPacket, error)
}

// gosnmpWrapper wraps a *gosnmp.GoSNMP object so we can use it as a snmpConnection.
type gosnmpWrapper struct {
	*gosnmp.GoSNMP
}

// Host returns the value of GoSNMP.Target.
func (gsw gosnmpWrapper) Host() string {
	return gsw.Target
}

// Walk wraps GoSNMP.Walk() or GoSNMP.BulkWalk(), depending on whether the
// connection is using SNMPv1 or newer.
// Also, if any error is encountered, it will just once reconnect and try again.
func (gsw gosnmpWrapper) Walk(oid string, fn gosnmp.WalkFunc) error {
	var err error
	// On error, retry once.
	// Unfortunately we can't distinguish between an error returned by gosnmp, and one returned by the walk function.
	for i := 0; i < 2; i++ {
		if gsw.Version == gosnmp.Version1 {
			err = gsw.GoSNMP.Walk(oid, fn)
		} else {
			err = gsw.GoSNMP.BulkWalk(oid, fn)
		}
		if err == nil {
			return nil
		}
		if err := gsw.GoSNMP.Connect(); err != nil {
			return fmt.Errorf("reconnecting %s", err)
		}
	}
	return err
}

// Get wraps GoSNMP.GET().
// If any error is encountered, it will just once reconnect and try again.
func (gsw gosnmpWrapper) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	var err error
	var pkt *gosnmp.SnmpPacket
	for i := 0; i < 2; i++ {
		pkt, err = gsw.GoSNMP.Get(oids)
		if err == nil {
			return pkt, nil
		}
		if err := gsw.GoSNMP.Connect(); err != nil {
			return nil, fmt.Errorf("reconnecting %s", err)
		}
	}
	return nil, err
}

// getConnection creates a snmpConnection (*gosnmp.GoSNMP) object and caches the
// result using `agent` as the cache key.
func (s *Snmp) getConnection(agent string) (snmpConnection, error) {
	if s.connectionCache == nil {
		s.connectionCache = map[string]snmpConnection{}
	}
	if gs, ok := s.connectionCache[agent]; ok {
		return gs, nil
	}

	gs := gosnmpWrapper{&gosnmp.GoSNMP{}}

	host, portStr, err := net.SplitHostPort(agent)
	if err != nil {
		if err, ok := err.(*net.AddrError); !ok || err.Err != "missing port in address" {
			return nil, fmt.Errorf("reconnecting %s", err)
		}
		host = agent
		portStr = "161"
	}
	gs.Target = host

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("reconnecting %s", err)
	}
	gs.Port = uint16(port)

	if s.Timeout != "" {
		if gs.Timeout, err = time.ParseDuration(s.Timeout); err != nil {
			return nil, fmt.Errorf("reconnecting %s", err)
		}
	} else {
		gs.Timeout = time.Second * 1
	}

	gs.Retries = s.Retries

	switch s.Version {
	case 3:
		gs.Version = gosnmp.Version3
	case 2, 0:
		gs.Version = gosnmp.Version2c
	case 1:
		gs.Version = gosnmp.Version1
	default:
		return nil, fmt.Errorf("invalid version")
	}

	if s.Version < 3 {
		if s.Community == "" {
			gs.Community = "public"
		} else {
			gs.Community = s.Community
		}
	}

	gs.MaxRepetitions = int(s.MaxRepetitions)

	if s.Version == 3 {
		gs.ContextName = s.ContextName

		sp := &gosnmp.UsmSecurityParameters{}
		gs.SecurityParameters = sp
		gs.SecurityModel = gosnmp.UserSecurityModel

		switch strings.ToLower(s.SecLevel) {
		case "noauthnopriv", "":
			gs.MsgFlags = gosnmp.NoAuthNoPriv
		case "authnopriv":
			gs.MsgFlags = gosnmp.AuthNoPriv
		case "authpriv":
			gs.MsgFlags = gosnmp.AuthPriv
		default:
			return nil, fmt.Errorf("invalid secLevel")
		}

		sp.UserName = s.SecName

		switch strings.ToLower(s.AuthProtocol) {
		case "md5":
			sp.AuthenticationProtocol = gosnmp.MD5
		case "sha":
			sp.AuthenticationProtocol = gosnmp.SHA
		case "":
			sp.AuthenticationProtocol = gosnmp.NoAuth
		default:
			return nil, fmt.Errorf("invalid authProtocol")
		}

		sp.AuthenticationPassphrase = s.AuthPassword

		switch strings.ToLower(s.PrivProtocol) {
		case "des":
			sp.PrivacyProtocol = gosnmp.DES
		case "aes":
			sp.PrivacyProtocol = gosnmp.AES
		case "":
			sp.PrivacyProtocol = gosnmp.NoPriv
		default:
			return nil, fmt.Errorf("invalid privProtocol")
		}

		sp.PrivacyPassphrase = s.PrivPassword
	}

	if err := gs.Connect(); err != nil {
		return nil, fmt.Errorf("setting up connection %s", err)
	}

	s.connectionCache[agent] = gs
	return gs, nil
}

// fieldConvert converts from any type according to the conv specification
//  "float"/"float(0)" will convert the value into a float.
//  "float(X)" will convert the value into a float, and then move the decimal before Xth right-most digit.
//  "int" will convert the value into an integer.
//  "string" will convert any interface to a string.
// Any other conv will return the input value unchanged.
func fieldConvert(conv string, v interface{}) interface{} {
	if conv == "string" {
		switch vt := v.(type) {
		case []byte:
			v = string(vt)
		case int:
			v = strconv.Itoa(vt)
		default:
			v = fmt.Sprint(v)
		}
	}

	var d int
	if _, err := fmt.Sscanf(conv, "float(%d)", &d); err == nil || conv == "float" {
		switch vt := v.(type) {
		case float32:
			v = float64(vt) / math.Pow10(d)
		case float64:
			v = float64(vt) / math.Pow10(d)
		case int:
			v = float64(vt) / math.Pow10(d)
		case int8:
			v = float64(vt) / math.Pow10(d)
		case int16:
			v = float64(vt) / math.Pow10(d)
		case int32:
			v = float64(vt) / math.Pow10(d)
		case int64:
			v = float64(vt) / math.Pow10(d)
		case uint:
			v = float64(vt) / math.Pow10(d)
		case uint8:
			v = float64(vt) / math.Pow10(d)
		case uint16:
			v = float64(vt) / math.Pow10(d)
		case uint32:
			v = float64(vt) / math.Pow10(d)
		case uint64:
			v = float64(vt) / math.Pow10(d)
		case []byte:
			vf, _ := strconv.ParseFloat(string(vt), 64)
			v = vf / math.Pow10(d)
		case string:
			vf, _ := strconv.ParseFloat(vt, 64)
			v = vf / math.Pow10(d)
		}
	}
	if conv == "int" {
		switch vt := v.(type) {
		case float32:
			v = int64(vt)
		case float64:
			v = int64(vt)
		case int:
			v = int64(vt)
		case int8:
			v = int64(vt)
		case int16:
			v = int64(vt)
		case int32:
			v = int64(vt)
		case int64:
			v = int64(vt)
		case uint:
			v = int64(vt)
		case uint8:
			v = int64(vt)
		case uint16:
			v = int64(vt)
		case uint32:
			v = int64(vt)
		case uint64:
			v = int64(vt)
		case []byte:
			v, _ = strconv.Atoi(string(vt))
		case string:
			v, _ = strconv.Atoi(vt)
		}
	}

	return v
}

func copyTags(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func init() {
	bin, _ := exec.LookPath("snmptranslate")
	inputs.Add("snmp", func() telegraf.Input {
		return &Snmp{
			Retries:        5,
			MaxRepetitions: 50,
			translateBin:   bin,
			oidToMib:       make(map[string]string),
		}
	})
}
