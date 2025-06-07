import setuptools

with open("../../README.md") as fp:
    long_description = fp.read()

setuptools.setup(
    name="my_api_landing_cdk",
    version="0.1.0",
    description="AWS CDK app for My Landing API Gateway",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Michael Leedahl",
    package_dir={"": "."},
    packages=setuptools.find_packages(),
    install_requires=[
        "aws-apis_cdk-lib>=2.0.0",
        "constructs>=10.0.0",
    ],
    python_requires=">=3.12",
)