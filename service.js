exports.handler = async (event) => {
    console.log(event)
    // TODO implement
    const response = {
        statusCode: 200,
        body: JSON.stringify('Hello ' + event.requestContext.authorizer.tenant_id + ' to service 2'),
    };
    return response;
};