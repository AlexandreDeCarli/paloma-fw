package db

import (
	"testing"
)

func TestSplitSQLStatements(t *testing.T) {
	input := `
-- Comment line
CREATE TABLE test_one (id INT PRIMARY KEY);

# Another comment
CREATE TABLE test_two (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL
);
`
	statements := splitSQLStatements(input)
	if len(statements) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(statements))
	}

	if statements[0] != "CREATE TABLE test_one (id INT PRIMARY KEY);" {
		t.Errorf("unexpected statement 0: %q", statements[0])
	}
}
