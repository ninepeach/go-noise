package noise

// The standard patterns are exposed as functions that return deep copies, so no
// caller can modify the definitions this package validates against.

// HandshakeNN returns a fresh copy of the standard Noise NN pattern.
func HandshakeNN() HandshakePattern { return clonePattern(handshakeNN) }

// HandshakeKN returns a fresh copy of the standard Noise KN pattern.
func HandshakeKN() HandshakePattern { return clonePattern(handshakeKN) }

// HandshakeNK returns a fresh copy of the standard Noise NK pattern.
func HandshakeNK() HandshakePattern { return clonePattern(handshakeNK) }

// HandshakeKK returns a fresh copy of the standard Noise KK pattern.
func HandshakeKK() HandshakePattern { return clonePattern(handshakeKK) }

// HandshakeNX returns a fresh copy of the standard Noise NX pattern.
func HandshakeNX() HandshakePattern { return clonePattern(handshakeNX) }

// HandshakeKX returns a fresh copy of the standard Noise KX pattern.
func HandshakeKX() HandshakePattern { return clonePattern(handshakeKX) }

// HandshakeXN returns a fresh copy of the standard Noise XN pattern.
func HandshakeXN() HandshakePattern { return clonePattern(handshakeXN) }

// HandshakeIN returns a fresh copy of the standard Noise IN pattern.
func HandshakeIN() HandshakePattern { return clonePattern(handshakeIN) }

// HandshakeXK returns a fresh copy of the standard Noise XK pattern.
func HandshakeXK() HandshakePattern { return clonePattern(handshakeXK) }

// HandshakeIK returns a fresh copy of the standard Noise IK pattern.
func HandshakeIK() HandshakePattern { return clonePattern(handshakeIK) }

// HandshakeXX returns a fresh copy of the standard Noise XX pattern.
func HandshakeXX() HandshakePattern { return clonePattern(handshakeXX) }

// HandshakeXXfallback returns a fresh copy of the standard Noise XXfallback pattern.
func HandshakeXXfallback() HandshakePattern { return clonePattern(handshakeXXfallback) }

// HandshakeIX returns a fresh copy of the standard Noise IX pattern.
func HandshakeIX() HandshakePattern { return clonePattern(handshakeIX) }

// HandshakeN returns a fresh copy of the standard Noise N pattern.
func HandshakeN() HandshakePattern { return clonePattern(handshakeN) }

// HandshakeK returns a fresh copy of the standard Noise K pattern.
func HandshakeK() HandshakePattern { return clonePattern(handshakeK) }

// HandshakeX returns a fresh copy of the standard Noise X pattern.
func HandshakeX() HandshakePattern { return clonePattern(handshakeX) }

var handshakeNN = HandshakePattern{
	Name: "NN",
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE},
	},
}

var handshakeKN = HandshakePattern{
	Name:                 "KN",
	InitiatorPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE},
	},
}

var handshakeNK = HandshakePattern{
	Name:                 "NK",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES},
		{MessagePatternE, MessagePatternDHEE},
	},
}

var handshakeKK = HandshakePattern{
	Name:                 "KK",
	InitiatorPreMessages: []MessagePattern{MessagePatternS},
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES, MessagePatternDHSS},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE},
	},
}

var handshakeNX = HandshakePattern{
	Name: "NX",
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE, MessagePatternS, MessagePatternDHES},
	},
}

var handshakeKX = HandshakePattern{
	Name:                 "KX",
	InitiatorPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE, MessagePatternS, MessagePatternDHES},
	},
}

var handshakeXN = HandshakePattern{
	Name: "XN",
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE},
		{MessagePatternS, MessagePatternDHSE},
	},
}

var handshakeIN = HandshakePattern{
	Name: "IN",
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternS},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE},
	},
}

var handshakeXK = HandshakePattern{
	Name:                 "XK",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES},
		{MessagePatternE, MessagePatternDHEE},
		{MessagePatternS, MessagePatternDHSE},
	},
}

var handshakeIK = HandshakePattern{
	Name:                 "IK",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES, MessagePatternS, MessagePatternDHSS},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE},
	},
}

var handshakeXX = HandshakePattern{
	Name: "XX",
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE, MessagePatternS, MessagePatternDHES},
		{MessagePatternS, MessagePatternDHSE},
	},
}

var handshakeXXfallback = HandshakePattern{
	Name:                 "XXfallback",
	ResponderPreMessages: []MessagePattern{MessagePatternE},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHEE, MessagePatternS, MessagePatternDHSE},
		{MessagePatternS, MessagePatternDHES},
	},
}

var handshakeIX = HandshakePattern{
	Name: "IX",
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternS},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE, MessagePatternS, MessagePatternDHES},
	},
}

var handshakeN = HandshakePattern{
	Name:                 "N",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES},
	},
}

var handshakeK = HandshakePattern{
	Name:                 "K",
	InitiatorPreMessages: []MessagePattern{MessagePatternS},
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES, MessagePatternDHSS},
	},
}

var handshakeX = HandshakePattern{
	Name:                 "X",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES, MessagePatternS, MessagePatternDHSS},
	},
}

// A MessagePattern is a single message or operation used in a Noise handshake.
type MessagePattern int

// A HandshakePattern is a list of messages and operations that are used to
// perform a specific Noise handshake.
type HandshakePattern struct {
	Name                 string
	InitiatorPreMessages []MessagePattern
	ResponderPreMessages []MessagePattern
	Messages             [][]MessagePattern
}

const (
	MessagePatternS MessagePattern = iota
	MessagePatternE
	MessagePatternDHEE
	MessagePatternDHES
	MessagePatternDHSE
	MessagePatternDHSS
	MessagePatternPSK
)
