# Template Rust

A Rust project template featuring a todo application with SQLite database and terminal user interface (TUI).

## Features

- 📝 Todo management with SQLite persistence
- 🖥️ Interactive Terminal User Interface (TUI)
- 🔧 Command Line Interface (CLI)
- 🧪 Comprehensive test suite
- 🚀 CI/CD with GitHub Actions
- 📦 Cross-platform releases
- 🔒 Security auditing

## Installation

### From Source

```bash
git clone https://github.com/pnstack/template-rust.git
cd template-rust
cargo build --release
```

### From Releases

Download the latest binary from the [Releases](https://github.com/pnstack/template-rust/releases) page.

## Usage

### Command Line Interface

```bash
# Show help
./template-rust --help

# Add a new todo
./template-rust add "Buy groceries" --description "Milk, eggs, bread"

# List all todos
./template-rust list

# List only completed todos
./template-rust list --completed

# List only pending todos
./template-rust list --pending

# Complete a todo (use the ID from list command)
./template-rust complete <todo-id>

# Delete a todo
./template-rust delete <todo-id>

# Start interactive TUI (default mode)
./template-rust tui
```

### Terminal User Interface (TUI)

Start the interactive mode:

```bash
./template-rust tui
```

#### TUI Commands:
- `h` - Show help
- `n` - Add new todo
- `d` - Delete selected todo
- `c` - Toggle todo completion status
- `a` - Show all todos
- `p` - Show pending todos only
- `f` - Show completed todos only
- `↑↓` - Navigate todos
- `q` - Quit application

## Project Structure

```
template-rust/
├── .github/workflows/    # CI/CD workflows
├── src/
│   ├── database/         # Database layer
│   ├── models/           # Data models
│   ├── tui/              # Terminal UI
│   ├── lib.rs            # Library root
│   └── main.rs           # CLI application
├── tests/                # Integration tests
├── docs/                 # Documentation
└── examples/             # Usage examples
```

## Development

### Prerequisites

- Rust 1.70 or later
- SQLite3

### Building

```bash
cargo build
```

### Running Tests

```bash
cargo test
```

### Running Clippy (Linter)

```bash
cargo clippy -- -D warnings
```

### Formatting Code

```bash
cargo fmt
```

## Database

The application uses SQLite for persistence. By default, it creates a `todo.db` file in the current directory. You can specify a different database path:

```bash
./template-rust --database /path/to/your/todos.db list
```

For testing with in-memory database:

```bash
./template-rust --database ":memory:" add "Test todo"
```

## CI/CD

The project includes comprehensive GitHub Actions workflows:

- **CI**: Build, test, lint, and format checks on multiple platforms
- **Security**: Weekly security audits with `cargo audit`
- **Release**: Automated binary releases for Linux, macOS, and Windows

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
