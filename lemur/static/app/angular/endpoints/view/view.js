'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider.state('endpoints', {
      url: '/endpoints',
      templateUrl: '/angular/endpoints/view/view.tpl.html',
      controller: 'EndpointsViewController'
    });
  })

  .controller('EndpointsViewController', function ($q, $scope, $uibModal, EndpointApi, EndpointService, MomentService, ngTableParams, $window, toaster) {
    $scope.filter = {};
    $scope.endpointsTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        EndpointApi.getList(params.url()).then(
          function (data) {
            params.total(data.total);
            $defer.resolve(data);
          }
        );
      }
    });


    $scope.setActive = function (endpoint, active) {
      var action = active ? 'Reactivate' : 'Deactivate';
      var explanation = active ? 'This restores tracking without verifying the endpoint or changing the certificate or cloud resource.' :
        'This does not change the certificate or cloud resource. Source sync may reactivate it if rediscovered.';
      if (endpoint.updatingActive || endpoint.active === active || !$window.confirm(
        action + ' ' + endpoint.name + ' in Lemur? ' + explanation
      )) {
        return;
      }
      endpoint.updatingActive = true;
      return endpoint.post('active', {active: active}).then(function () {
        endpoint.active = active;
        toaster.pop({type: 'success', title: 'Endpoint ' + action.toLowerCase() + 'd', body: endpoint.name});
        return $scope.endpointsTable.reload();
      }, function (response) {
        toaster.pop({
          type: 'error',
          title: 'Unable to ' + action.toLowerCase() + ' endpoint',
          body: (response.data && response.data.message) || 'Please try again.'
        });
      }).finally(function () {
        endpoint.updatingActive = false;
      });
    };

    $scope.ciphers = [
      {'title': 'Protocol-SSLv2', 'id': 'Protocol-SSLv2'},
      {'title': 'Protocol-SSLv3', 'id': 'Protocol-SSLv3'},
      {'title': 'Protocol-TLSv1', 'id': 'Protocol-TLSv1'},
      {'title': 'Protocol-TLSv1.1', 'id': 'Protocol-TLSv1.1'},
      {'title': 'Protocol-TLSv1.2', 'id': 'Protocol-TLSv1.2'},
    ];

    $scope.momentService = MomentService;

    $scope.endpointService = EndpointService;

  });
