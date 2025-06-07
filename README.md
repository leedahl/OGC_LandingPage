# OGC LandingPage

AWS Lambda functions and CDK infrastructure for deploying an API Landing page.
The landing page describes various Application Programming Interfaces (APIs) developed by Michael Leedahl.
The intent of this website is to demonstrate various concepts for creating well-formed APIs and providing API documentation.

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
- Python 3.12 or higher

### Deploy the CDK Applications

This project contains two CDK applications:
- `apis_cdk`: Deploys the API Gateway and related resources
- `greeting_cdk`: Deploys the greeting API resources

#### Common Prerequisites for Both CDK Projects

1. Install the main project and its dependencies:

```bash
pip install -e .
```

#### Deploying the APIs CDK Project

1. Navigate to the APIs CDK directory:

```bash
cd cdks/apis_cdk
```

2. Install the CDK app dependencies (choose one method):

```bash
# Using setup.py
pip install -e .

# OR using requirements.txt
pip install -r requirements.txt
```

3. Bootstrap your AWS environment (if you haven't already):

```bash
cdk bootstrap
```

4. Deploy the stack:

```bash
cdk deploy
```

5. To destroy the stack when no longer needed:

```bash
cdk destroy
```

#### Deploying the Greeting CDK Project

1. Navigate to the Greeting CDK directory:

```bash
cd cdks/greeting_cdk
```

2. Install the CDK app dependencies (choose one method):

```bash
# Using setup.py
pip install -e .

# OR using requirements.txt
pip install -r requirements.txt
```

3. Bootstrap your AWS environment (if you haven't already):

```bash
cdk bootstrap
```

4. Deploy the stack:

```bash
cdk deploy
```

5. To destroy the stack when no longer needed:

```bash
cdk destroy
```

## License

MIT
