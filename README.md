# AuthPlusRBAC

AuthPlusRBAC is a Role-Based Access Control (RBAC) system implemented using Flask. It uses JSON Web Tokens (JWT) for session management and MongoDB for role-based authorization.

## Features

- Role-Based Access Control (RBAC)
- JSON Web Tokens (JWT) for session management
- MongoDB for storing roles and permissions
- Flask framework

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/AuthPlusRBAC.git
    cd AuthPlusRBAC
    ```

2. Create a virtual environment and activate it:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`

3. Install the dependencies:
    ```bash
    pip install -r requirements.txt
    ```

4. Set up MongoDB:
    - Ensure MongoDB is installed and running on your machine.
    - Update the MongoDB connection string in the configuration file.

## Usage

1. Run the Flask application:
    ```bash
    flask run
    ```

2. Access the application at `http://127.0.0.1:8000`.

3. There are three web pages: `re1`, `re2`, and `re3`. Experiment with creating, authorizing, and testing these pages. (available in resources section)

## Configuration

- Update the configuration settings in `config.py` to match your environment.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For any inquiries, please contact [sidkundargi@gmail.com](mailto:sidkundargi@gmail.com).
