const jsonwebtoken = require('jsonwebtoken');
const Axios = require('axios');
const jwkToPem = require('jwk-to-pem');
const util = require('util');


// let cacheKeys;

exports.handler = async (event, context, callback) => {

    let pools_map = new Map();
    pools_map.set('https://cognito-idp.us-east-1.amazonaws.com/us-east-1_l1VBiCirS', 'tenant_a');
    pools_map.set('https://cognito-idp.us-east-1.amazonaws.com/us-east-1_PJrGwBMw6', 'tenant_b');

    var token = event.authorizationToken.split(" ")[1];

    var decodedToken = jsonwebtoken.decode(token);
    console.log(decodedToken);

    const tokenSections = token.split('.');

    //Step 1: Confirm the Structure of the JWT 
    if (tokenSections.length < 2) { throw new Error('requested token is invalid'); }

    // //Step 2: Validate the JWT Signature 
    const headerJSON = Buffer.from(tokenSections[0], 'base64').toString('utf8');
    const header = JSON.parse(headerJSON);
    // const keys = getPublicKeysSimple(decodedToken.iss);
    const keys = await getPublicKeys(decodedToken.iss);
    const key = keys[header.kid];
    if (key === undefined) {
        throw new Error('claim made for unknown kid');
    }

    const claim = await verifyPromised(token, key.pem);

    //Step 3: Verify the Claims 
    const currentSeconds = Math.floor((new Date()).valueOf() / 1000);
    if (currentSeconds > decodedToken.exp || currentSeconds < decodedToken.auth_time) {
        throw new Error('claim is expired or invalid');
    }
    if (!pools_map.has(decodedToken.iss)) {
        // if (claim.iss !== cognitoIssuer) {
        throw new Error('claim issuer is invalid');
    }
    if (decodedToken.token_use !== 'id') {
        throw new Error('claim use is not id');
    }
    console.log(`claim confirmed for ${decodedToken.email}`);

    callback(null, buildAllowAllPolicy(event, decodedToken.sub, pools_map.get(decodedToken.iss)));
}

const verifyPromised = util.promisify(jsonwebtoken.verify.bind(jsonwebtoken));

const getPublicKeys = async (issuerUrl) => {
    const url = `${issuerUrl}/.well-known/jwks.json`;
    const publicKeys = await Axios.default.get(url);
    let cacheKeys = publicKeys.data.keys.reduce((agg, current) => {
        const pem = jwkToPem(current);
        agg[current.kid] = { instance: current, pem };
        return agg;
    }, {});
    return cacheKeys;
};

function buildAllowAllPolicy(event, principalId, tenantid) {
    console.log(tenantid);
    var apiOptions = {}
    var tmp = event.methodArn.split(':')
    var apiGatewayArnTmp = tmp[5].split('/')
    var awsAccountId = tmp[4]
    var awsRegion = tmp[3]
    var restApiId = apiGatewayArnTmp[0]
    var stage = apiGatewayArnTmp[1]
    var apiArn = 'arn:aws:execute-api:' + awsRegion + ':' + awsAccountId + ':' +
        restApiId + '/' + stage + '/*/*'
    const policy = {
        principalId: principalId,
        policyDocument: {
            Version: '2012-10-17',
            Statement: [
                {
                    Action: 'execute-api:Invoke',
                    Effect: 'Allow',
                    Resource: [apiArn]
                }
            ]
        },
        context: {
            tenant_id: tenantid
        }
    }
    return policy
}

function denyAllPolicy() {
    return {
        "principalId": "*",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "*",
                    "Effect": "Deny",
                    "Resource": "*"
                }
            ]
        }
    }
}