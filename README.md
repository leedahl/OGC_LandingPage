# My APIs

AWS Lambda functions and CDK infrastructure for deploying an API Landing page.
The landing page describes various Application Programming Interfaces (APIs) developed by Michael Leedahl.
The intent of this website is to demonstrate various concepts for creating well-formed APIs.

## Description

This project contains AWS Lambda functions for handling API Gateway requests, including:

- `greeting_lambda`: A simple Lambda function that returns a greeting message
- `authorizer_lambda`: A Lambda function that handles API Gateway authorization

It also includes an AWS CDK application for deploying these Lambda functions as part of an API Gateway with proper authorization.

## Installation

```bash
pip install -e .
```

## Development

For development, install the package with development dependencies:

```bash
pip install -e ".[dev]"
```

## Testing

Run tests using pytest:

```bash
pytest
```

## Deployment

### Prerequisites

- AWS CLI configured with appropriate credentials
- AWS CDK installed (`npm install -g aws-cdk`)
- Python 3.8 or higher

### Deploy the CDK Application

1. Install the project and its dependencies:

```bash
pip install -e .
```

2. Navigate to the CDK directory:

```bash
cd apis_cdk
```

3. Install the CDK app dependencies (choose one method):

```bash
# Using setup.py
pip install -e .

# OR using requirements.txt
pip install -r requirements.txt
```

4. Bootstrap your AWS environment (if you haven't already):

```bash
apis_cdk bootstrap
```

5. Deploy the stack:

```bash
apis_cdk deploy
```

6. To destroy the stack when no longer needed:

```bash
apis_cdk destroy
```

## License

MIT
