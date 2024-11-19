import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { aws_apigateway } from 'aws-cdk-lib';
import { aws_lambda } from 'aws-cdk-lib';
import { InstanceClass, InstanceSize, InstanceType, Peer, Port, SecurityGroup, SubnetType, Vpc } from 'aws-cdk-lib/aws-ec2';
import { Credentials, DatabaseInstance, DatabaseInstanceEngine, MysqlEngineVersion } from 'aws-cdk-lib/aws-rds';
import { Secret } from 'aws-cdk-lib/aws-secretsmanager';
import { aws_cognito } from 'aws-cdk-lib';
import { data } from "../config/cdk-config.json";
import * as iam from "aws-cdk-lib/aws-iam";
import { aws_dynamodb as dynamodb } from "aws-cdk-lib"
import { aws_s3 as s3 } from "aws-cdk-lib"
import { DynamoEventSource } from 'aws-cdk-lib/aws-lambda-event-sources';
import * as sns from 'aws-cdk-lib/aws-sns';


export class CdkStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // RDS Configuration files
    const engine = DatabaseInstanceEngine.mysql({ version: MysqlEngineVersion.VER_5_7 });
    const instanceType = InstanceType.of(InstanceClass.T3, InstanceSize.MICRO);


    // Create master user details
    const userSecret = new Secret(this, "db-user-credentials", {
      secretName: "catalogue/mysql/secretDb",
      description: "Database user creadentials",
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ username: "admin" }),
        generateStringKey: "password",
        passwordLength: 16,
        excludePunctuation: true
      }
    });
    cdk.Tags.of(userSecret).add("Name", "Catalogue-Application")

    // VPC
    const cofigVPC = Vpc.fromLookup(this, "config-vpc", { vpcId: data.vpcId });

    // Create Security Group
    const dbSecurityGroup = new SecurityGroup(this, "RDS-SG", {
      securityGroupName: "RDS-SG",
      vpc: cofigVPC
    });
    cdk.Tags.of(dbSecurityGroup).add("Name", "Catalogue-Application")

    // adding Inbound rule
    dbSecurityGroup.addIngressRule(
      Peer.ipv4(cofigVPC.vpcCidrBlock),
      Port.tcp(data.port),
      `Allow port ${data.port} for database connection form only within the VPC`
    );

    // Creating RDS instance
    const dbInstance = new DatabaseInstance(this, 'catalogue-application', {
      vpc: cofigVPC,
      vpcSubnets: { subnetType: SubnetType.PUBLIC },
      instanceType,
      engine,
      securityGroups: [dbSecurityGroup],
      databaseName: data.database,
      credentials: Credentials.fromSecret(userSecret)
    })
    cdk.Tags.of(dbInstance).add("Name", "Catalogue-Application")

    // DynamoDB Table
    const manageContentTable = new dynamodb.Table(this, 'manage-content-table', {
      tableName: 'content-tables',
      partitionKey: {
        name: 'VENDOR_ID',
        type: dynamodb.AttributeType.STRING
      },
      sortKey: {
        name: 'PRODUCT_ID',
        type: dynamodb.AttributeType.STRING
      },
      
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
    })
    manageContentTable.addGlobalSecondaryIndex({
      indexName: 'category-index',
      partitionKey: {name: 'GSI', type: dynamodb.AttributeType.STRING},
      sortKey: {name: 'CATEGORY_NAME', type: dynamodb.AttributeType.STRING},
      readCapacity: 1,
      writeCapacity: 1,
      projectionType: dynamodb.ProjectionType.ALL,
    });
    cdk.Tags.of(manageContentTable).add("Name", "Catalogue-Application")

    //DynamoDB table for criteria
    const manageCriteriaTable = new dynamodb.Table(this, 'manage-criteria', {
      tableName: 'criteria',
      partitionKey: {
        name: 'PK',
        type: dynamodb.AttributeType.STRING
      },
      sortKey: {
        name: 'SK',
        type: dynamodb.AttributeType.STRING
      }
    })
    cdk.Tags.of(manageCriteriaTable).add("Name", "Catalogue-Application")

    // S3 Bucket for Content Image
    const imageBucket = new s3.Bucket(this, 'imageBucket', {
      bucketName: 'catalogue-content-image-data-321'
    });

    cdk.Tags.of(imageBucket).add("Name", "Catalogue-Application")

    imageBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        principals: [new iam.ServicePrincipal('lambda.amazonaws.com')],
        actions: [
          "s3:GetObject"
        ],
        effect: iam.Effect.ALLOW,
        resources: [`${imageBucket.bucketArn}/*`]
      })
    )

    // S3 Bucket for Content CSV File
    const csvFileBucket = new s3.Bucket(this, 'csvFileBucket', {
      bucketName: 'catalogue-content-csv-file'
    });

    cdk.Tags.of(csvFileBucket).add("Name", "Catalogue-Application")

    csvFileBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        principals: [new iam.ServicePrincipal('lambda.amazonaws.com')],
        actions: [
          "s3:PutObject"
        ],
        effect: iam.Effect.ALLOW,
        resources: [`${csvFileBucket.bucketArn}/*`]
      })
    )

    // SNS Topic for Notification
    const snsTopic = new sns.Topic(this, 'snsTopic', {
      displayName: 'Violated Content',
      topicName: 'Violated-Content'
    });


    // Old API Gateway Integration
    const api = new aws_apigateway.RestApi(this, 'Catalogue_Application', {
      defaultCorsPreflightOptions: {
        allowHeaders: [
          'Content-Type',
          'X-Amz-Date',
          'Authorization',
          'X-Api-Key',
        ],
        allowMethods: ['OPTIONS', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
        allowOrigins: ['*'],
      },
    });

    api.addGatewayResponse('4XX-gateway-response', {
      type: aws_apigateway.ResponseType.DEFAULT_4XX
    })

    api.addGatewayResponse('5XX-gateway-response', {
      type: aws_apigateway.ResponseType.DEFAULT_5XX
    })

    cdk.Tags.of(api).add("Name", "Catalogue-Application")

    // New API Gateway Integration
    const api_gateway = new aws_apigateway.SpecRestApi(this, 'Catalogue_Api', {
      apiDefinition: aws_apigateway.ApiDefinition.fromAsset('OpenApi/Catalogue_Application-apigateway.json')
    });
  
    api_gateway.addGatewayResponse('4XX-response', {
      type: aws_apigateway.ResponseType.DEFAULT_4XX
    })
  
    api_gateway.addGatewayResponse('5XX-response', {
      type: aws_apigateway.ResponseType.DEFAULT_5XX
    })

    cdk.Tags.of(api_gateway).add("Name", "Catalogue-Application")

    // Resources for HTTP API methods
    const adminResource = api.root.addResource('admin');
    const categoryResource = api.root.addResource('categories');
    const signUpResource = api.root.addResource('signUp');
    const confirmSignUpResource = api.root.addResource('confirmSignUp');
    const loginResource = api.root.addResource('login');
    const contentProviderResource = api.root.addResource('content-provider');
    const forgotPasswordResource = api.root.addResource('forgot-password');
    const confirmPasswordResource = api.root.addResource('confirm-password');
    const signOutResource = api.root.addResource('logout');
    const manageContent = api.root.addResource('contents');
    const listViolatedContentApi = api.root.addResource('violated-content');
    const requestResource = api.root.addResource('requests');
    const dashboardResource = api.root.addResource('dashboard');
    const resetPasswordResponse = api.root.addResource('reset-password')
    const manageCriteria = api.root.addResource('criteria');
    const userResource = api.root.addResource('users');
    const openSearchResource = api.root.addResource('search')


    // RDS Role for Lambda
    const cognitoCreateAdminRole = new iam.PolicyDocument({
      statements: [new iam.PolicyStatement({
        actions: [
          "cognito-idp:AdminCreateUser"
        ],
        effect: iam.Effect.ALLOW,
        resources: ["*"]
      })]
    })


    const SecretManager_Readonly = new iam.PolicyDocument({
      statements: [new iam.PolicyStatement({
        actions: [
          "secretsmanager:GetRandomPassword",
          "secretsmanager:GetResourcePolicy",
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecretVersionIds",
          "secretsmanager:ListSecrets"
        ],
        effect: iam.Effect.ALLOW,
        resources: ["*"]
      })]
    })

    const OpenSearchPolicy = new iam.PolicyDocument({
      statements: [new iam.PolicyStatement({
        actions: [
          "aoss:CreateCollection",
          "aoss:ListCollections",
          "aoss:BatchGetCollection",
          "aoss:UpdateCollection",
          "aoss:DeleteCollection",
          "aoss:CreateAccessPolicy",
          "aoss:CreateSecurityPolicy"
        ],
        effect: iam.Effect.ALLOW,
        resources: ["*"]
      })]
    })

    const cognitoAdmin = new iam.PolicyDocument({
      statements: [new iam.PolicyStatement({
        actions: [
          "cognito-idp:AdminEnableUser",
          "cognito-idp:AdminDisableUser",
          "cognito-idp:AdminDeleteUser",
          "cognito-idp:AdminRespondToAuthChallenge",
          "cognito-idp:adminSetUserPassword",
          "cognito-idp:adminResetUserPassword",
          "cognito-idp:adminUpdateUserAttributes",
          "cognito-idp:AdminInitiateAuth",
          "cognito-idp:InitiateAuth"
        ],
        effect: iam.Effect.ALLOW,
        resources: ["*"]
      })]
    })

    const cognitoAddUserToGroup = new iam.PolicyDocument({
      statements: [new iam.PolicyStatement({
        actions: [
          "cognito-idp:AdminAddUserToGroup",
          "cognito-idp:AdminConfirmSignUp",
          "cognito-idp:AdminGetUser",
        ],
        effect: iam.Effect.ALLOW,
        resources: ["*"]
      })]
    })


    const rdsRole = new iam.Role(this, "RdsRole", {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      roleName: "LambdaDataAccessRoleForRDS",
      inlinePolicies: {
        CognitoCreateAdminRole: cognitoCreateAdminRole,
        SecretManager_Readonly: SecretManager_Readonly,
        CognitoAdmin: cognitoAdmin,
        addUsertoGroup: cognitoAddUserToGroup
      }
    })

    rdsRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonRDSDataFullAccess"))
    rdsRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("CloudWatchFullAccess"))
    rdsRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("AWSLambdaExecute"))

    cdk.Tags.of(rdsRole).add("Name", "Catalogue-Application")

    const openSearchRole = new iam.Role(this, "openSearchRole", {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      roleName: "LambdaRoleForOpenSearch",
      inlinePolicies: {
        SecretManager_Readonly: SecretManager_Readonly,
        OpenSearchPolicy: OpenSearchPolicy
      }
    })
    openSearchRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("CloudWatchFullAccess"))
    openSearchRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("AWSLambdaExecute"))
    openSearchRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonDynamoDBFullAccess"))

    // Lambda Role for S3 & DynamoDB
    const LambdaS3Policy = new iam.PolicyDocument({
      statements: [new iam.PolicyStatement({
        actions: [
          "s3:DeleteObject",
          "s3:GetObject",
          "s3:GetObjectAttributes",
          "s3:GetObjectVersion",
          "s3:GetObjectVersionAttributes",
          "s3:PutBucketCORS",
          "s3:PutBucketVersioning",
          "s3:PutObject",

        ],
        effect: iam.Effect.ALLOW,
        resources: [`${imageBucket.bucketArn}/*`]
      })]
    })

    // Lambda Role for S3 & DynamoDB for csvFileBucket
    const LambdaS3CSVUploadPolicy = new iam.PolicyDocument({
      statements: [new iam.PolicyStatement({
        actions: [
          "s3:DeleteObject",
          "s3:GetObject",
          "s3:GetObjectAttributes",
          "s3:GetObjectVersion",
          "s3:GetObjectVersionAttributes",
          "s3:PutBucketCORS",
          "s3:PutBucketVersioning",
          "s3:PutObject",

        ],
        effect: iam.Effect.ALLOW,
        resources: [`${csvFileBucket.bucketArn}/*`]
      })]
    })

    const LambdaDynamoPolicy = new iam.PolicyDocument({
      statements: [new iam.PolicyStatement({
        actions: [
          "dynamodb:BatchGetItem",
          "dynamodb:BatchWriteItem",
          "dynamodb:DeleteItem",
          "dynamodb:GetItem",
          "dynamodb:GetRecords",
          "dynamodb:ListTables",
          "dynamodb:PutItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:UpdateItem",
          "dynamodb:UpdateTable"
        ],
        effect: iam.Effect.ALLOW,
        resources: [manageContentTable.tableArn]
      })]
    })

    const LambdaRoleForS3_Dynamo = new iam.Role(this, "LambdaRoleForS3_Dynamo", {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      roleName: "LambdaRoleForS3_Dynamo",
      inlinePolicies: {
        s3Policy: LambdaS3Policy
      }

    })
    LambdaRoleForS3_Dynamo.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("CloudWatchFullAccess"))
    LambdaRoleForS3_Dynamo.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonDynamoDBFullAccess"))

    cdk.Tags.of(LambdaRoleForS3_Dynamo).add("Name", "Catalogue-Application")

    const LambdaRoleForS3_Dynamo_CSV_File = new iam.Role(this, "LambdaRoleForS3_Dynamo_CSV_File", {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      roleName: "LambdaRoleForS3_Dynamo_CSV_File",
      inlinePolicies: {
        s3Policy: LambdaS3CSVUploadPolicy,
        dynamoPolicy: LambdaDynamoPolicy
      }

    })

    LambdaRoleForS3_Dynamo_CSV_File.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("CloudWatchFullAccess"))
    cdk.Tags.of(LambdaRoleForS3_Dynamo_CSV_File).add("Name", "Catalogue-Application")

    const LambdaDynamoForCriteriaPolicy = new iam.PolicyDocument({
      statements: [new iam.PolicyStatement({
        actions: [
          "dynamodb:BatchGetItem",
          "dynamodb:BatchWriteItem",
          "dynamodb:DeleteItem",
          "dynamodb:GetItem",
          "dynamodb:GetRecords",
          "dynamodb:ListTables",
          "dynamodb:PutItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:UpdateItem",
          "dynamodb:UpdateTable"
        ],
        effect: iam.Effect.ALLOW,
        resources: [manageCriteriaTable.tableArn]
      })]
    })

    const LambdaRoleForDynamo = new iam.Role(this, "LambdaRoleForDynamo", {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      roleName: "LambdaRoleForDynamo",
      inlinePolicies: {
        criteriaDynamoPolicy: LambdaDynamoForCriteriaPolicy
      }

    })
    LambdaRoleForDynamo.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("CloudWatchFullAccess"))
    cdk.Tags.of(LambdaRoleForDynamo).add("Name", "Catalogue-Application")

    const LambdaRoleForNotification = new iam.Role(this, "LambdaRoleForNotification", {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      roleName: "LambdaRoleForNotification",
      inlinePolicies: {
        dynamoPolicyForContent: LambdaDynamoPolicy,
        dynamoPolicyForCriteria: LambdaDynamoForCriteriaPolicy
      }
    })
    LambdaRoleForNotification.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("CloudWatchFullAccess"))
    cdk.Tags.of(LambdaRoleForNotification).add("Name", "Catalogue-Application")


    // Cognito userpool for Admin signup
    const cognitoUserpool = new aws_cognito.UserPool(this, 'catalogue-app-userpool', {
      userPoolName: 'catalogue-app-pool',
      selfSignUpEnabled: true,
      signInAliases: {
        email: true,
      },
      autoVerify: {
        email: true,
      },
      standardAttributes: {
        fullname: {
          required: true,
          mutable: true,
        },
        email: {
          required: true,
          mutable: true,
        },
        phoneNumber: {
          required: true,
          mutable: true,
        },

      },
      passwordPolicy: {
        minLength: 6,
        requireLowercase: true,
        requireDigits: true,
        requireUppercase: true,
        requireSymbols: true,
      },
      accountRecovery: aws_cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // APP Client for Cognito
    const appClient = cognitoUserpool.addClient('app-client', {
      userPoolClientName: "catalogue-application-client"
    })

    // Groups in Cognito Userpool
    const adminGroup = new aws_cognito.CfnUserPoolGroup(this, 'admin-userpool-group', {
      userPoolId: cognitoUserpool.userPoolId,
      groupName: "admin",
      description: "Admin will able to manage User as well as Content Provider & will also be able to manage all the activities of the Catalog App."
    })

    const contentProviderGroup = new aws_cognito.CfnUserPoolGroup(this, 'content-provider-userpool-group', {
      userPoolId: cognitoUserpool.userPoolId,
      groupName: "content-provider",
      description: "Content provider will be able to view & manage the content & will be able to manage the categories on the Catalog App"
    })

    const userPoolGroup = new aws_cognito.CfnUserPoolGroup(this, 'user-userpool-group', {
      userPoolId: cognitoUserpool.userPoolId,
      groupName: "user",
      description: "User will be able to view the content on the Catalog App"
    })

    cdk.Tags.of(cognitoUserpool).add("Name", "Catalogue-Application")

    // Lambda Layer integration
    const dependenciesLayer = new aws_lambda.LayerVersion(this, 'dependencies-layer', {
      compatibleRuntimes: [
        aws_lambda.Runtime.NODEJS_14_X,
        aws_lambda.Runtime.NODEJS_16_X,
      ],
      code: aws_lambda.Code.fromAsset('layers/dependencies'),
      description: 'Uses a 3rd party library called sql',
    });

    const auth = new aws_apigateway.CognitoUserPoolsAuthorizer(this, 'apiAuthorizer', {
      cognitoUserPools: [cognitoUserpool]
    });

    cdk.Tags.of(dependenciesLayer).add("Name", "Catalogue-Application")
    // Lambda Layer integration
    const commonFunctionLayer = new aws_lambda.LayerVersion(this, 'common-function-layer', {
      compatibleRuntimes: [
        aws_lambda.Runtime.NODEJS_14_X,
        aws_lambda.Runtime.NODEJS_16_X,
      ],
      code: aws_lambda.Code.fromAsset('layers/common-functions'),
      description: 'Uses common function within the application',
    });

    cdk.Tags.of(commonFunctionLayer).add("Name", "Catalogue-Application")

    // Create global for lambda function
    const global = {
      runtime: aws_lambda.Runtime.NODEJS_16_X,
      handler: 'index.handler',
      timeout: cdk.Duration.seconds(25),
      layers: [dependenciesLayer, commonFunctionLayer],
      environment: {
        LD_LIBRARY_PATH: "/opt:$LD_LIBRARY_PATH",
        SECRET_MANAGER: userSecret.secretName
      }
    }
    // Add Admin Lambda
    const addAdmin = new aws_lambda.Function(this, 'addAdmin', {
      ...global, ...{
        functionName: "add-admin",
        code: aws_lambda.Code.fromAsset('lambda/manage-admin/add-admin'),
        role: rdsRole,
        environment: {
          ...{
            USER_POOL_ID: cognitoUserpool.userPoolId,
            CLIENT_ID: appClient.userPoolClientId
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(addAdmin).add("Name", "Catalogue-Application")

    // POST method integration with lambda function
    // adminResource.addMethod('POST', new aws_apigateway.LambdaIntegration(addAdmin), {
    //   authorizer: auth,
    //   authorizationType: aws_apigateway.AuthorizationType.COGNITO
    // });

    // Block unblock all content of content Provider Lambda
    const blockUnblockAllContent = new aws_lambda.Function(this, 'block-unblock-content', {
      ...global, ...{
        functionName: "block-unblock-content-of-content-provider",
        code: aws_lambda.Code.fromAsset('lambda/manage-content/block-unblock-content-of-content-provider'),
        role: LambdaRoleForS3_Dynamo,
        environment: {
          ...{
            MANAGE_CONTENT_TABLE_NAME: manageContentTable.tableName
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(blockUnblockAllContent).add("Name", "Catalogue-Application")
    //Invoke Lambda Policy
    const invokeFunctionPolicy = new iam.Policy(this, "invokeFunction", {
      statements: [new iam.PolicyStatement({
        actions: [
          "lambda:GetFunction",
          "lambda:InvokeAsync",
          "lambda:InvokeFunction",
          "lambda:InvokeFunctionUrl"
        ],
        effect: iam.Effect.ALLOW,
        resources: [blockUnblockAllContent.functionArn]
      })]
    })
    rdsRole.attachInlinePolicy(invokeFunctionPolicy);

    //get-data-from-opensearch
    const getDataFromOpenSearch = new aws_lambda.Function(this, 'get-data-from-opensearch', {
      ...global, ...{
        functionName: "get-content-from-opensearch",
        code: aws_lambda.Code.fromAsset('lambda/manage-opensearch/get-data-from-opensearch'),
        role: openSearchRole,
        environment: {
          ...{
            MANAGE_CONTENT_TABLE_NAME: manageContentTable.tableName

          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(getDataFromOpenSearch).add("Name", "Catalogue-Application")
    // GET method integration with lambda function
    openSearchResource.addMethod('GET', new aws_apigateway.LambdaIntegration(getDataFromOpenSearch), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    });

    //put-data-into-opensearch
    const putDataIntoOpenSearch = new aws_lambda.Function(this, 'put-data-in-open-search', {
      ...global, ...{
        functionName: "put-data-in-opensearch",
        code: aws_lambda.Code.fromAsset('lambda/manage-opensearch/put-data-into-opensearch'),
        role: openSearchRole,
        environment: {
          ...{
            MANAGE_CONTENT_TABLE_NAME: manageContentTable.tableName

          }, ...global.environment
        }
      }
    });
    putDataIntoOpenSearch.addEventSource(new DynamoEventSource(manageContentTable, {
      startingPosition: aws_lambda.StartingPosition.LATEST,
      batchSize:10
    }));
    cdk.Tags.of(putDataIntoOpenSearch).add("Name", "Catalogue-Application")

    // get-user-detail Lambda
    const getUsersDetail = new aws_lambda.Function(this, 'getUsersDetail', {
      ...{
        functionName: "get-users-detail",
        code: aws_lambda.Code.fromAsset('lambda/user/get-users-detail'),
        role: rdsRole
      }, ...global
    });
    cdk.Tags.of(getUsersDetail).add("Name", "Catalogue-Application")

    // GET method integration with lambda function
    // userResource.addMethod('POST', new aws_apigateway.LambdaIntegration(getUsersDetail), {
    //   authorizer: auth,
    //   authorizationType: aws_apigateway.AuthorizationType.COGNITO
    // });

    // List Lambda
    const listAdmin = new aws_lambda.Function(this, 'listAdmin', {
      ...{
        functionName: "list-admin",
        code: aws_lambda.Code.fromAsset('lambda/manage-admin/list-admin'),
        role: rdsRole
      }, ...global
    });
    cdk.Tags.of(listAdmin).add("Name", "Catalogue-Application")


    // const adminResource = usersResource.addResource('admin')

    // adminResource.addMethod('GET', new aws_apigateway.LambdaIntegration(listAdmin))


    // GET method integration with lambda function
    adminResource.addMethod('GET', new aws_apigateway.LambdaIntegration(listAdmin), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    });

    // Reset-Password Lambda
    const resetPassword = new aws_lambda.Function(this, 'resetPassword', {
      ...global, ...{
        functionName: "reset-password",
        code: aws_lambda.Code.fromAsset('lambda/auth/reset-password'),
        role: rdsRole,
        environment: {
          ...{
            USER_POOL_ID: cognitoUserpool.userPoolId,
            CLIENT_ID: appClient.userPoolClientId,
            SNS_TOPIC_ARN: snsTopic.topicArn
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(resetPassword).add("Name", "Catalogue-Application")

    // POST method integration with lambda function
    resetPasswordResponse.addMethod('POST', new aws_apigateway.LambdaIntegration(resetPassword));

    // AddCategory Lambda
    const addCategory = new aws_lambda.Function(this, 'addCategory', {
      ...{
        functionName: 'add-category',
        code: aws_lambda.Code.fromAsset('lambda/manage-category/add-category'),
        role: rdsRole
      }, ...global
    });
    cdk.Tags.of(addCategory).add("Name", "Catalogue-Application")

    // POST method integration with lambda function
    categoryResource.addMethod('POST', new aws_apigateway.LambdaIntegration(addCategory), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    });

    // ListCategory Lambda
    const listCategory = new aws_lambda.Function(this, 'listCategory', {
      ...{
        functionName: 'list-category',
        code: aws_lambda.Code.fromAsset('lambda/manage-category/list-category'),
        role: rdsRole
      }, ...global
    });

    cdk.Tags.of(listCategory).add("Name", "Catalogue-Application")
    // POST method integration with lambda function
    categoryResource.addMethod('GET', new aws_apigateway.LambdaIntegration(listCategory), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    });

    // Creating Tables in DB Instance Lambda
    const createDbTables = new aws_lambda.Function(this, 'createDbTables', {
      ...{
        functionName: "create-db-tables",
        code: aws_lambda.Code.fromAsset('lambda/db-tables/create-tables'),
        role: rdsRole
      }, ...global
    });
    cdk.Tags.of(createDbTables).add("Name", "Catalogue-Application")

    // Add User To Group Lambda
    const addUserToGroup = new aws_lambda.Function(this, 'addUserToGroup', {
      ...{
        functionName: "add-user-to-group",
        code: aws_lambda.Code.fromAsset('lambda/user-group/add-user-to-group'),
        role: rdsRole
      }, ...global
    });
    cdk.Tags.of(addUserToGroup).add("Name", "Catalogue-Application")

    cognitoUserpool.addTrigger(aws_cognito.UserPoolOperation.POST_CONFIRMATION, addUserToGroup)

    // Login Lambda
    const login = new aws_lambda.Function(this, 'login', {
      ...global, ...{
        functionName: "login-lambda",
        code: aws_lambda.Code.fromAsset('lambda/auth/login'),
        role: rdsRole,
        environment: {
          ...{
            USER_POOL_ID: cognitoUserpool.userPoolId,
            CLIENT_ID: appClient.userPoolClientId
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(login).add("Name", "Catalogue-Application")

    loginResource.addMethod('POST', new aws_apigateway.LambdaIntegration(login));

    // Sign Up Lambda
    const signUpUser = new aws_lambda.Function(this, 'signUpUser', {
      ...global, ...{
        functionName: "sign-up-user",
        code: aws_lambda.Code.fromAsset('lambda/auth/sign-up-user'),
        role: rdsRole,
        environment: {
          ...{
            USER_POOL_ID: cognitoUserpool.userPoolId,
            CLIENT_ID: appClient.userPoolClientId
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(signUpUser).add("Name", "Catalogue-Application")
    // POST method integration with lambda function
    signUpResource.addMethod('POST', new aws_apigateway.LambdaIntegration(signUpUser));


    // Confirm Sign Up Lambda
    const confirmUser = new aws_lambda.Function(this, 'confirmUser', {
      ...global, ...{
        functionName: "confirm-user",
        code: aws_lambda.Code.fromAsset('lambda/auth/confirm-user'),
        role: rdsRole,
        environment: {
          ...{
            USER_POOL_ID: cognitoUserpool.userPoolId,
            CLIENT_ID: appClient.userPoolClientId
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(confirmUser).add("Name", "Catalogue-Application")

    // POST method integration with lambda function
    confirmSignUpResource.addMethod('POST', new aws_apigateway.LambdaIntegration(confirmUser));

    // Listing Content Provider Lambda
    const listContentProvider = new aws_lambda.Function(this, 'listContentProvider', {
      ...{
        functionName: "list-content-provider",
        code: aws_lambda.Code.fromAsset('lambda/manage-content-provider/list-content-provider'),
        role: rdsRole
      }, ...global
    });
    cdk.Tags.of(listContentProvider).add("Name", "Catalogue-Application")


    // GET method integration with lambda function
    contentProviderResource.addMethod('GET', new aws_apigateway.LambdaIntegration(listContentProvider), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    });

    // Forgot Password Lambda
    const forgotpassword = new aws_lambda.Function(this, 'forgotpassword', {
      ...global, ...{
        functionName: "forgot-password",
        code: aws_lambda.Code.fromAsset('lambda/auth/forgot-password'),
        role: rdsRole,
        environment: {
          ...{
            USER_POOL_ID: cognitoUserpool.userPoolId,
            CLIENT_ID: appClient.userPoolClientId
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(forgotpassword).add("Name", "Catalogue-Application")

    // POST method integration with lambda function
    forgotPasswordResource.addMethod('POST', new aws_apigateway.LambdaIntegration(forgotpassword));

    // Confirm Password Lambda
    const confirmpassword = new aws_lambda.Function(this, 'confirmpassword', {
      ...global, ...{
        functionName: "confirm-password",
        code: aws_lambda.Code.fromAsset('lambda/auth/confirm-password'),
        role: rdsRole,
        environment: {
          ...{
            USER_POOL_ID: cognitoUserpool.userPoolId,
            CLIENT_ID: appClient.userPoolClientId
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(confirmpassword).add("Name", "Catalogue-Application")

    // POST method integration with lambda function
    confirmPasswordResource.addMethod('POST', new aws_apigateway.LambdaIntegration(confirmpassword));

    // Sign out Lambda
    const signOutUser = new aws_lambda.Function(this, 'signOutUser', {
      ...global, ...{
        functionName: "sign-out-user",
        code: aws_lambda.Code.fromAsset('lambda/auth/sign-out-user'),
        role: rdsRole,
        environment: {
          ...{
            CLIENT_ID: appClient.userPoolClientId
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(signOutUser).add("Name", "Catalogue-Application")

    // POST method integration with lambda function
    signOutResource.addMethod('POST', new aws_apigateway.LambdaIntegration(signOutUser));

    // add content Lambda
    const addContent = new aws_lambda.Function(this, 'addContent', {
      ...global, ...{
        functionName: "add-content",
        code: aws_lambda.Code.fromAsset('lambda/manage-content/add-content'),
        role: LambdaRoleForS3_Dynamo,
        environment: {
          ...{
            MANAGE_CONTENT_TABLE_NAME: manageContentTable.tableName,
            S3_BUCKET_NAME: imageBucket.bucketName
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(addContent).add("Name", "Catalogue-Application")

    // POST method integration with lambda function
    manageContent.addMethod('POST', new aws_apigateway.LambdaIntegration(addContent), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    })


    // update content Lambda
    const updateContent = new aws_lambda.Function(this, 'updateContent', {
      ...global, ...{
        functionName: "update-content",
        code: aws_lambda.Code.fromAsset('lambda/manage-content/update-content'),
        role: LambdaRoleForS3_Dynamo,
        environment: {
          ...{
            MANAGE_CONTENT_TABLE_NAME: manageContentTable.tableName,
            S3_BUCKET_NAME: imageBucket.bucketName
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(updateContent).add("Name", "Catalogue-Application")
    // PUT method integration with lambda function
    const productId = manageContent.addResource('{product_id}')
    productId.addMethod('PUT', new aws_apigateway.LambdaIntegration(updateContent), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    })

    // delete content Lambda
    const deleteContent = new aws_lambda.Function(this, 'deleteContent', {
      ...global, ...{
        functionName: "delete-content",
        code: aws_lambda.Code.fromAsset('lambda/manage-content/delete-content'),
        role: LambdaRoleForS3_Dynamo,
        environment: {
          ...{
            MANAGE_CONTENT_TABLE_NAME: manageContentTable.tableName,
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(deleteContent).add("Name", "Catalogue-Application")
    productId.addMethod('DELETE', new aws_apigateway.LambdaIntegration(deleteContent), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    })

    // bulk upload content Lambda
    const bulkUploadContent = new aws_lambda.Function(this, 'bulkUploadContent', {
      ...global, ...{
        functionName: "bulk-upload-content",
        code: aws_lambda.Code.fromAsset('lambda/manage-content/bulk-upload-content'),
        role: LambdaRoleForS3_Dynamo_CSV_File,
        environment: {
          ...{
            MANAGE_CONTENT_TABLE_NAME: manageContentTable.tableName,
            S3_BUCKET_NAME: csvFileBucket.bucketName
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(bulkUploadContent).add("Name", "Catalogue-Application")

    // POST method integration with lambda function
    manageContent.addMethod('PATCH', new aws_apigateway.LambdaIntegration(bulkUploadContent), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    })

    // block content Lambda
    const blockContent = new aws_lambda.Function(this, 'blockContent', {
      ...global, ...{
        functionName: "block-content",
        code: aws_lambda.Code.fromAsset('lambda/manage-content/block-content'),
        role: LambdaRoleForS3_Dynamo,
        environment: {
          ...{
            MANAGE_CONTENT_TABLE_NAME: manageContentTable.tableName,
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(blockContent).add("Name", "Catalogue-Application")

    // PATCH method integration with lambda function
    productId.addMethod('PATCH', new aws_apigateway.LambdaIntegration(blockContent), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    })



    // list content Lambda
    const listContent = new aws_lambda.Function(this, 'listContent', {
      ...global, ...{
        functionName: "list-content",
        code: aws_lambda.Code.fromAsset('lambda/manage-content/list-content'),
        role: LambdaRoleForS3_Dynamo,
        environment: {
          ...{
            MANAGE_CONTENT_TABLE_NAME: manageContentTable.tableName
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(listContent).add("Name", "Catalogue-Application")

    // GET method
    manageContent.addMethod('GET', new aws_apigateway.LambdaIntegration(listContent), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    })


    // block content provider
    const blockContentProvider = new aws_lambda.Function(this, 'blockContentProvider', {
      ...global, ...{
        functionName: "block-content-provider",
        code: aws_lambda.Code.fromAsset('lambda/manage-content-provider/block-content-provider'),
        role: rdsRole,
        environment: {
          ...{
            InvokeFunctionARN: blockUnblockAllContent.functionArn,
            USER_POOL_ID: cognitoUserpool.userPoolId
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(blockContentProvider).add("Name", "Catalogue-Application")

    // PUT method integration with lambda function
    contentProviderResource.addMethod('PUT', new aws_apigateway.LambdaIntegration(blockContentProvider), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    });

    // Fetching Dashboard
    const dashboard = new aws_lambda.Function(this, 'manage-dashboard', {
      ...{
        functionName: "manage-dashboard",
        code: aws_lambda.Code.fromAsset('lambda/manage-dashboard'),
        role: rdsRole
      }, ...global
    });
    cdk.Tags.of(dashboard).add("Name", "Catalogue-Application")

    // GET method integration with lambda function
    dashboardResource.addMethod('GET', new aws_apigateway.LambdaIntegration(dashboard));

    //delete content-provider
    const deleteContentProvider = new aws_lambda.Function(this, 'deleteContentProvider', {
      ...global, ...{
        functionName: "delete-content-provider",
        code: aws_lambda.Code.fromAsset('lambda/manage-content-provider/delete-content-provider'),
        role: rdsRole,
        environment: {
          ...{
            USER_POOL_ID: cognitoUserpool.userPoolId
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(deleteContentProvider).add("Name", "Catalogue-Application")

    // PUT method integration with lambda function
    contentProviderResource.addMethod('PATCH', new aws_apigateway.LambdaIntegration(deleteContentProvider), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    });


    // list new content provider
    const listContentProviderRequest = new aws_lambda.Function(this, 'pendingContentProviderRequest', {
      ...global, ...{
        functionName: "pending-content-provider-request",
        code: aws_lambda.Code.fromAsset('lambda/manage-content-provider/pending-request'),
        role: rdsRole
      }, ...global
    });
    cdk.Tags.of(listContentProviderRequest).add("Name", "Catalogue-Application")

    // GET method integration with lambda function
    requestResource.addMethod('GET', new aws_apigateway.LambdaIntegration(listContentProviderRequest), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    });

    // approve deny new content provider
    const approveDenyContentProviderRequest = new aws_lambda.Function(this, 'approveDenyContentProviderRequest', {
      ...global, ...{
        functionName: "approve-deny-content-provider-request",
        code: aws_lambda.Code.fromAsset('lambda/manage-content-provider/approve-deny-request'),
        role: rdsRole,
        environment: {
          ...{
            USER_POOL_ID: cognitoUserpool.userPoolId,
            CLIENT_ID: appClient.userPoolClientId
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(approveDenyContentProviderRequest).add("Name", "Catalogue-Application")
    // POST method integration with lambda function
    requestResource.addMethod('POST', new aws_apigateway.LambdaIntegration(approveDenyContentProviderRequest), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    });

    //add criteria lambda
    const addCriteria = new aws_lambda.Function(this, 'addCriteria', {
      ...global, ...{
        functionName: "add-criteria",
        code: aws_lambda.Code.fromAsset('lambda/manage-criteria/add-criteria'),
        role: LambdaRoleForDynamo,
        environment: {
          ...{
            MANAGE_CRITERIA_TABLE_NAME: manageCriteriaTable.tableName,
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(addCriteria).add("Name", "Catalogue-Application")

    // POST method integration with lambda function
    manageCriteria.addMethod('POST', new aws_apigateway.LambdaIntegration(addCriteria), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    })
    // list violated content Lambda
    const listViolatedContent = new aws_lambda.Function(this, 'listViolatedContent', {
      ...global, ...{
        functionName: "list-violated-content",
        code: aws_lambda.Code.fromAsset('lambda/list-violated-content'),
        role: LambdaRoleForS3_Dynamo,
        environment: {
          ...{
            VOILATED_CRITERIA_CONTENT_TABLE_NAME: manageContentTable.tableName
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(listViolatedContent).add("Name", "Catalogue-Application")
    //POST method integration with lambda function
    listViolatedContentApi.addMethod('POST', new aws_apigateway.LambdaIntegration(listViolatedContent), {
        authorizer: auth,
        authorizationType: aws_apigateway.AuthorizationType.COGNITO
      })

    //list criteria lambda
    const listCriteria = new aws_lambda.Function(this, 'listCriteria', {
      ...global, ...{
        functionName: "list-criteria",
        code: aws_lambda.Code.fromAsset('lambda/manage-criteria/list-criteria'),
        role: LambdaRoleForDynamo,
        environment: {
          ...{
            MANAGE_CRITERIA_TABLE_NAME: manageCriteriaTable.tableName,
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(listCriteria).add("Name", "Catalogue-Application")

    // GET method integration with lambda function
    manageCriteria.addMethod('GET', new aws_apigateway.LambdaIntegration(listCriteria), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    })

    //enable-disable criteria lambda
    const enableDisableCriteria = new aws_lambda.Function(this, 'enableDisableCriteria', {
      ...global, ...{
        functionName: "enable-disable-criteria",
        code: aws_lambda.Code.fromAsset('lambda/manage-criteria/enable-disable-criteria'),
        role: LambdaRoleForDynamo,
        environment: {
          ...{
            MANAGE_CRITERIA_TABLE_NAME: manageCriteriaTable.tableName,
          }, ...global.environment
        }
      }
    });
    cdk.Tags.of(enableDisableCriteria).add("Name", "Catalogue-Application")

    // Patch method integration with lambda function
    manageCriteria.addMethod('PATCH', new aws_apigateway.LambdaIntegration(enableDisableCriteria), {
      authorizer: auth,
      authorizationType: aws_apigateway.AuthorizationType.COGNITO
    })

    //check-criteria criteria lambda
    const checkCriteria = new aws_lambda.Function(this, 'checkCriteria', {
      ...global, ...{
        functionName: "check-criteria",
        code: aws_lambda.Code.fromAsset('lambda/manage-criteria/check-criteria'),
        role: LambdaRoleForNotification,
        environment: {
          ...{
            MANAGE_CRITERIA_TABLE_NAME: manageCriteriaTable.tableName,
            MANAGE_CONTENT_TABLE_NAME: manageContentTable.tableName,
            SNS_TOPIC_ARN: snsTopic.topicArn
          }, ...global.environment
        }
      }
    });
    checkCriteria.addEventSource(new DynamoEventSource(manageContentTable, {
      startingPosition: aws_lambda.StartingPosition.LATEST,
      filters: [aws_lambda.FilterCriteria.filter({ eventName: aws_lambda.FilterRule.isEqual('MODIFY') })],
      batchSize:10
    }));
    cdk.Tags.of(checkCriteria).add("Name", "Catalogue-Application")
    const addDatatoOpenSearch = new aws_lambda.Function(this, 'add-data-to-open-search', {
      ...global, ...{
        functionName: "add-data-to-opensearch",
        code: aws_lambda.Code.fromAsset('lambda/manage-opensearch/add-data-to-opensearch'),
        role: openSearchRole,
        environment: {
          ...{
            MANAGE_CONTENT_TABLE_NAME: manageContentTable.tableName

          }, ...global.environment
        }
      }
    });
    
    cdk.Tags.of(addDatatoOpenSearch).add("Name", "Catalogue-Application")
 
  }
};
