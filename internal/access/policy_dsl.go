// Package access - Inline policy DSL parser and evaluator for zero-trust access decisions
package access

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// PolicyContext holds all variables available to policy expressions
type PolicyContext struct {
	UserEmail     string
	UserRoles     []string
	RequestIP     string
	DeviceTrusted bool
	PostureScore  float64
	TimeHour      int
	GeoCountry    string
	RiskScore     int
	RequestMethod string
	RequestPath   string
}

// PolicyNode is the interface for all AST nodes
type PolicyNode interface {
	Evaluate(ctx *PolicyContext) (bool, error)
	String() string
}

// ---- AST Node types ----

type andNode struct{ left, right PolicyNode }
type orNode struct{ left, right PolicyNode }
type notNode struct{ child PolicyNode }

type comparisonNode struct {
	variable string
	operator string
	value    interface{} // string, float64, bool, []string
}

func (n *andNode) Evaluate(ctx *PolicyContext) (bool, error) {
	l, err := n.left.Evaluate(ctx)
	if err != nil {
		return false, err
	}
	if !l {
		return false, nil
	}
	return n.right.Evaluate(ctx)
}
func (n *andNode) String() string { return fmt.Sprintf("(%s AND %s)", n.left, n.right) }

func (n *orNode) Evaluate(ctx *PolicyContext) (bool, error) {
	l, err := n.left.Evaluate(ctx)
	if err != nil {
		return false, err
	}
	if l {
		return true, nil
	}
	return n.right.Evaluate(ctx)
}
func (n *orNode) String() string { return fmt.Sprintf("(%s OR %s)", n.left, n.right) }

func (n *notNode) Evaluate(ctx *PolicyContext) (bool, error) {
	val, err := n.child.Evaluate(ctx)
	if err != nil {
		return false, err
	}
	return !val, nil
}
func (n *notNode) String() string { return fmt.Sprintf("NOT %s", n.child) }

func (n *comparisonNode) Evaluate(ctx *PolicyContext) (bool, error) {
	varVal := resolveVariable(n.variable, ctx)
	return compareValues(varVal, n.operator, n.value)
}
func (n *comparisonNode) String() string {
	return fmt.Sprintf("%s %s %v", n.variable, n.operator, n.value)
}

// ---- Variable resolution ----

func resolveVariable(name string, ctx *PolicyContext) interface{} {
	switch name {
	case "user.email":
		return ctx.UserEmail
	case "user.roles":
		return ctx.UserRoles
	case "request.ip":
		return ctx.RequestIP
	case "device.trusted":
		return ctx.DeviceTrusted
	case "device.posture_score":
		return ctx.PostureScore
	case "time.hour":
		return float64(ctx.TimeHour)
	case "geo.country":
		return ctx.GeoCountry
	case "session.risk_score":
		return float64(ctx.RiskScore)
	case "request.method":
		return ctx.RequestMethod
	case "request.path":
		return ctx.RequestPath
	default:
		return nil
	}
}

// ---- Comparison logic ----

func compareValues(left interface{}, op string, right interface{}) (bool, error) {
	switch op {
	case "==":
		return fmt.Sprintf("%v", left) == fmt.Sprintf("%v", right), nil
	case "!=":
		return fmt.Sprintf("%v", left) != fmt.Sprintf("%v", right), nil
	case "in":
		return evalIn(left, right)
	case "not_in":
		result, err := evalIn(left, right)
		return !result, err
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", left), fmt.Sprintf("%v", right)), nil
	case "matches":
		pattern, ok := right.(string)
		if !ok {
			return false, fmt.Errorf("matches operator requires a string pattern")
		}
		if len(pattern) > 200 {
			return false, fmt.Errorf("regex pattern too long (%d chars, max 200)", len(pattern))
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
		}
		return re.MatchString(fmt.Sprintf("%v", left)), nil
	case ">", "<", ">=", "<=":
		return evalNumericComparison(left, op, right)
	default:
		return false, fmt.Errorf("unknown operator %q", op)
	}
}

func evalIn(left, right interface{}) (bool, error) {
	arr, ok := right.([]string)
	if !ok {
		return false, fmt.Errorf("in/not_in operator requires an array value")
	}

	// If left is a []string (e.g. user.roles), check if any element is in the array
	if leftArr, ok := left.([]string); ok {
		for _, lv := range leftArr {
			for _, rv := range arr {
				if lv == rv {
					return true, nil
				}
			}
		}
		return false, nil
	}

	// Scalar comparison
	leftStr := fmt.Sprintf("%v", left)
	for _, rv := range arr {
		if leftStr == rv {
			return true, nil
		}
	}
	return false, nil
}

func evalNumericComparison(left interface{}, op string, right interface{}) (bool, error) {
	lf, err := toFloat64(left)
	if err != nil {
		return false, fmt.Errorf("left operand for %s must be numeric: %w", op, err)
	}
	rf, err := toFloat64(right)
	if err != nil {
		return false, fmt.Errorf("right operand for %s must be numeric: %w", op, err)
	}

	switch op {
	case ">":
		return lf > rf, nil
	case "<":
		return lf < rf, nil
	case ">=":
		return lf >= rf, nil
	case "<=":
		return lf <= rf, nil
	default:
		return false, nil
	}
}

func toFloat64(v interface{}) (float64, error) {
	switch val := v.(type) {
	case float64:
		return val, nil
	case int:
		return float64(val), nil
	case bool:
		if val {
			return 1, nil
		}
		return 0, nil
	case string:
		return strconv.ParseFloat(val, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", v)
	}
}

// ---- Tokenizer ----

type tokenType int

const (
	tokEOF tokenType = iota
	tokAND
	tokOR
	tokNOT
	tokLParen
	tokRParen
	tokOperator
	tokString
	tokNumber
	tokBool
	tokVariable
	tokLBracket
	tokRBracket
	tokComma
)

type token struct {
	typ tokenType
	val string
}

func tokenize(input string) ([]token, error) {
	var tokens []token
	i := 0
	runes := []rune(input)

	for i < len(runes) {
		ch := runes[i]

		// Skip whitespace
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			i++
			continue
		}

		// Parentheses and brackets
		if ch == '(' {
			tokens = append(tokens, token{tokLParen, "("})
			i++
			continue
		}
		if ch == ')' {
			tokens = append(tokens, token{tokRParen, ")"})
			i++
			continue
		}
		if ch == '[' {
			tokens = append(tokens, token{tokLBracket, "["})
			i++
			continue
		}
		if ch == ']' {
			tokens = append(tokens, token{tokRBracket, "]"})
			i++
			continue
		}
		if ch == ',' {
			tokens = append(tokens, token{tokComma, ","})
			i++
			continue
		}

		// Quoted string
		if ch == '"' {
			j := i + 1
			for j < len(runes) && runes[j] != '"' {
				if runes[j] == '\\' {
					j++ // skip escaped character
				}
				j++
			}
			if j >= len(runes) {
				return nil, fmt.Errorf("unterminated string starting at position %d", i)
			}
			val := string(runes[i+1 : j])
			val = strings.ReplaceAll(val, `\"`, `"`)
			tokens = append(tokens, token{tokString, val})
			i = j + 1
			continue
		}

		// Multi-character operators
		if i+1 < len(runes) {
			twoChar := string(runes[i : i+2])
			switch twoChar {
			case "==", "!=", ">=", "<=":
				tokens = append(tokens, token{tokOperator, twoChar})
				i += 2
				continue
			}
		}

		// Single-character operators
		if ch == '>' || ch == '<' {
			tokens = append(tokens, token{tokOperator, string(ch)})
			i++
			continue
		}

		// Word (keyword, variable, operator name, boolean, number)
		if isWordChar(ch) || ch == '-' || ch == '.' {
			j := i
			for j < len(runes) && (isWordChar(runes[j]) || runes[j] == '.' || runes[j] == '_' || runes[j] == '-') {
				j++
			}
			word := string(runes[i:j])

			switch strings.ToUpper(word) {
			case "AND":
				tokens = append(tokens, token{tokAND, "AND"})
			case "OR":
				tokens = append(tokens, token{tokOR, "OR"})
			case "NOT":
				tokens = append(tokens, token{tokNOT, "NOT"})
			case "TRUE":
				tokens = append(tokens, token{tokBool, "true"})
			case "FALSE":
				tokens = append(tokens, token{tokBool, "false"})
			case "IN", "NOT_IN", "CONTAINS", "MATCHES":
				tokens = append(tokens, token{tokOperator, strings.ToLower(word)})
			default:
				// Try to parse as number
				if _, err := strconv.ParseFloat(word, 64); err == nil {
					tokens = append(tokens, token{tokNumber, word})
				} else {
					tokens = append(tokens, token{tokVariable, word})
				}
			}
			i = j
			continue
		}

		return nil, fmt.Errorf("unexpected character %q at position %d", ch, i)
	}

	tokens = append(tokens, token{tokEOF, ""})
	return tokens, nil
}

func isWordChar(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_'
}

// ---- Recursive-descent parser ----

type parser struct {
	tokens []token
	pos    int
}

func (p *parser) peek() token {
	if p.pos >= len(p.tokens) {
		return token{tokEOF, ""}
	}
	return p.tokens[p.pos]
}

func (p *parser) advance() token {
	t := p.peek()
	p.pos++
	return t
}

func (p *parser) expect(typ tokenType) (token, error) {
	t := p.advance()
	if t.typ != typ {
		return t, fmt.Errorf("expected token type %d but got %d (%q) at position %d", typ, t.typ, t.val, p.pos-1)
	}
	return t, nil
}

// ParsePolicy parses a DSL expression string into an evaluable AST
func ParsePolicy(expr string) (PolicyNode, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("empty policy expression")
	}

	tokens, err := tokenize(expr)
	if err != nil {
		return nil, fmt.Errorf("tokenization error: %w", err)
	}

	p := &parser{tokens: tokens}
	node, err := p.parseOrExpr()
	if err != nil {
		return nil, err
	}

	if p.peek().typ != tokEOF {
		return nil, fmt.Errorf("unexpected token %q at position %d", p.peek().val, p.pos)
	}

	return node, nil
}

func (p *parser) parseOrExpr() (PolicyNode, error) {
	left, err := p.parseAndExpr()
	if err != nil {
		return nil, err
	}

	for p.peek().typ == tokOR {
		p.advance()
		right, err := p.parseAndExpr()
		if err != nil {
			return nil, err
		}
		left = &orNode{left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseAndExpr() (PolicyNode, error) {
	left, err := p.parseNotExpr()
	if err != nil {
		return nil, err
	}

	for p.peek().typ == tokAND {
		p.advance()
		right, err := p.parseNotExpr()
		if err != nil {
			return nil, err
		}
		left = &andNode{left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseNotExpr() (PolicyNode, error) {
	if p.peek().typ == tokNOT {
		p.advance()
		child, err := p.parseNotExpr()
		if err != nil {
			return nil, err
		}
		return &notNode{child: child}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (PolicyNode, error) {
	if p.peek().typ == tokLParen {
		p.advance()
		node, err := p.parseOrExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tokRParen); err != nil {
			return nil, fmt.Errorf("missing closing parenthesis")
		}
		return node, nil
	}

	return p.parseComparison()
}

func (p *parser) parseComparison() (PolicyNode, error) {
	varTok := p.advance()
	if varTok.typ != tokVariable {
		return nil, fmt.Errorf("expected variable name but got %q at position %d", varTok.val, p.pos-1)
	}

	opTok := p.advance()
	if opTok.typ != tokOperator {
		return nil, fmt.Errorf("expected operator but got %q at position %d", opTok.val, p.pos-1)
	}

	value, err := p.parseValue()
	if err != nil {
		return nil, err
	}

	return &comparisonNode{
		variable: varTok.val,
		operator: opTok.val,
		value:    value,
	}, nil
}

func (p *parser) parseValue() (interface{}, error) {
	t := p.peek()

	switch t.typ {
	case tokString:
		p.advance()
		return t.val, nil
	case tokNumber:
		p.advance()
		f, _ := strconv.ParseFloat(t.val, 64)
		return f, nil
	case tokBool:
		p.advance()
		return t.val == "true", nil
	case tokLBracket:
		return p.parseArray()
	default:
		return nil, fmt.Errorf("expected value but got %q at position %d", t.val, p.pos)
	}
}

func (p *parser) parseArray() ([]string, error) {
	if _, err := p.expect(tokLBracket); err != nil {
		return nil, err
	}

	var arr []string

	if p.peek().typ == tokRBracket {
		p.advance()
		return arr, nil
	}

	for {
		t := p.advance()
		if t.typ != tokString {
			return nil, fmt.Errorf("expected string in array but got %q at position %d", t.val, p.pos-1)
		}
		arr = append(arr, t.val)

		if p.peek().typ == tokComma {
			p.advance()
			continue
		}
		break
	}

	if _, err := p.expect(tokRBracket); err != nil {
		return nil, fmt.Errorf("missing closing bracket in array")
	}

	return arr, nil
}

// EvaluatePolicy evaluates a parsed policy AST against a context
func EvaluatePolicy(node PolicyNode, ctx *PolicyContext) (bool, error) {
	return node.Evaluate(ctx)
}

// EvaluatePolicyString parses and evaluates a policy expression in one call
func EvaluatePolicyString(expr string, ctx *PolicyContext) (bool, error) {
	node, err := ParsePolicy(expr)
	if err != nil {
		return false, fmt.Errorf("policy parse error: %w", err)
	}
	return EvaluatePolicy(node, ctx)
}

// ValidatePolicy checks if a policy expression is syntactically valid
func ValidatePolicy(expr string) error {
	_, err := ParsePolicy(expr)
	return err
}
