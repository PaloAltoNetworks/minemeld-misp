console.log('Loading mmmisp WebUI');

(function() {

function MISPSideConfigController($scope, MinemeldConfigService, MineMeldRunningConfigStatusService,
                                  toastr, $modal, ConfirmService, $timeout) {
    var vm = this;

    // side config settings
    vm.verify_cert = undefined;
    vm.automation_key = undefined;
    vm.url = undefined;

    vm.clientCertSet = undefined;
    vm.clientCertEnabled = undefined;

    vm.loadSideConfig = function() {
        var nodename = $scope.$parent.vm.nodename;

        MinemeldConfigService.getDataFile(nodename + '_side_config')
        .then((result) => {
            if (!result) {
                return;
            }

            if (result.automation_key) {
                vm.automation_key = result.automation_key;
            } else {
                vm.automation_key = undefined;
            }

            if (typeof result.verify_cert !== 'undefined') {
                vm.verify_cert = result.verify_cert;
            } else {
                vm.verify_cert = undefined;
            }

            if (result.url) {
                vm.url = result.url;
            } else {
                vm.url = undefined;
            }
        }, (error) => {
            toastr.error('ERROR RETRIEVING NODE SIDE CONFIG: ' + error.status);
            vm.automation_key = undefined;
            vm.verify_cert = undefined;
        })
        .finally(vm.checkClientCertificate);
    };

    vm.saveSideConfig = function() {
        var side_config = {};
        var hup_node = undefined;
        var nodename = $scope.$parent.vm.nodename;

        if (vm.automation_key) {
            side_config.automation_key = vm.automation_key;
        }

        if (vm.url) {
            side_config.url = vm.url;
        }

        if (typeof vm.verify_cert !== 'undefined') {
            side_config.verify_cert = vm.verify_cert;
        }

        return MinemeldConfigService.saveDataFile(
            nodename + '_side_config',
            side_config
        );
    };

    vm.checkClientCertificate = function() {
        var client_cert_required = false;
        var nodename = $scope.$parent.vm.nodename;

        MineMeldRunningConfigStatusService.getStatus().then((result) => {
            var node = result.nodes[nodename];

            vm.clientCertSet = false;
            vm.clientCertEnabled = false;

            if (node.resolvedPrototype && node.resolvedPrototype.config) {
                if (typeof node.resolvedPrototype.config.client_cert_required !== 'undefined') {
                    client_cert_required = node.resolvedPrototype.config.client_cert_required;
                }
            }

            if (node.node.config) {
                if (typeof node.node.config.client_cert_required !== 'undefined') {
                    client_cert_required = node.node.config.client_cert_required;
                }
            }

            if (!client_cert_required) {
                return;
            }

            vm.clientCertEnabled = true;

            MinemeldConfigService.getDataFile(nodename, 'cert').then((result) => {
                if (result == null) {
                    vm.clientCertSet = false;
                    return;
                }

                MinemeldConfigService.getDataFile(nodename, 'pkey').then((result) => {
                    if (result == null) {
                        vm.clientCertSet = false;
                        return;
                    }

                    vm.clientCertSet = true;
                }, (error) => {
                    vm.clientCertSet = false;
                });
            }, (error) => {
                vm.clientCertSet = false;
            });
        });
    };

    vm.setAutomationKey = function() {
        var mi = $modal.open({
            templateUrl: '/extensions/webui/mmmispWebui/misp.miner.sak.modal.html',
            controller: ['$modalInstance', MISPAutomationKeyController],
            controllerAs: 'vm',
            bindToController: true,
            backdrop: 'static',
            animation: false
        });

        mi.result.then((result) => {
            vm.automation_key = result.automation_key;

            return vm.saveSideConfig();
        })
        .then((result) => {
            toastr.success('AUTOMATION KEY SET');
            vm.loadSideConfig();
        }, (error) => {
            toastr.error('ERROR SETTING AUTOMATION KEY: ' + error.statusText);
        });
    };

    vm.setURL = function() {
        var mi = $modal.open({
            templateUrl: '/extensions/webui/mmmispWebui/misp.miner.surl.modal.html',
            controller: ['$modalInstance', MISPURLController],
            controllerAs: 'vm',
            bindToController: true,
            backdrop: 'static',
            animation: false
        });

        mi.result.then((result) => {
            vm.url = result.url;

            return vm.saveSideConfig();
        })
        .then(() => {
            toastr.success('URL SET');
            vm.loadSideConfig();
        }, (error) => {
            toastr.error('ERROR SETTING URL: ' + error.statusText);
        });
    };

    vm.toggleCertificateVerification = function() {
        var p, new_value;

        if (typeof this.verify_cert === 'undefined' || this.verify_cert) {
            new_value = false;
            p = ConfirmService.show(
                'MISP CERT VERIFICATION',
                'Are you sure you want to disable certificate verification ?'
            );
        } else {
            new_value = true;
            p = ConfirmService.show(
                'MISP CERT VERIFICATION',
                'Are you sure you want to enable certificate verification ?'
            );
        }

        p.then((result) => {
            vm.verify_cert = new_value;

            return vm.saveSideConfig().then((result) => {
                toastr.success('CERT VERIFICATION TOGGLED');
                vm.loadSideConfig();
            }, (error) => {
                toastr.error('ERROR TOGGLING CERT VERIFICATION: ' + error.statusText);
            });
        });
    };

    vm.uploadClientCertificate = function() {
        var mi;

        mi = $modal.open({
            templateUrl: '/extensions/webui/mmmispWebui/misp.miner.uploadcert.modal.html',
            controller: ['$modalInstance', 'FileUploader', 'toastr', 'nodeName', MISPUploadClientCertController],
            controllerAs: 'vm',
            bindToController: true,
            backdrop: 'static',
            animation: false,
            resolve: {
                nodeName: () => { return $scope.$parent.vm.nodename; }
            }
        });

        mi.result.then((result) => {
            vm.loadSideConfig();
        });
    }

    vm.loadSideConfig();
}

function MISPAutomationKeyController($modalInstance) {
    var vm = this;

    vm.automation_key = undefined;
    vm.automation_key2 = undefined;

    vm.valid = function() {
        if (vm.automation_key !== vm.automation_key2) {
            angular.element('#fgPassword1').addClass('has-error');
            angular.element('#fgPassword2').addClass('has-error');

            return false;
        }
        angular.element('#fgPassword1').removeClass('has-error');
        angular.element('#fgPassword2').removeClass('has-error');

        if (!vm.automation_key) {
            return false;
        }

        return true;
    };

    vm.save = function() {
        var result = {};

        result.automation_key = vm.automation_key;

        $modalInstance.close(result);
    }

    vm.cancel = function() {
        $modalInstance.dismiss();
    }
}

function MISPURLController($modalInstance, url) {
    var vm = this;

    vm.url = url;

    vm.valid = function() {
        angular.element('#url').removeClass('has-error');

        if (!vm.url) {
            return false;
        }

        return true;
    };

    vm.save = function() {
        var result = {};

        result.url = vm.url;

        $modalInstance.close(result);
    }

    vm.cancel = function() {
        $modalInstance.dismiss();
    }
}

function MISPUploadClientCertController($modalInstance, FileUploader, toastr, nodeName) {
    var vm = this;

    vm.uploading = false;
    vm.certUploader = undefined;
    vm.keyUploader = undefined;

    vm.uploadAll = function() {
        vm.uploading = true;
        vm.certUploader.uploadAll();
    }

    vm.cancel = function() {
        $modalInstance.dismiss('cancel');
    }

    vm.onErrorItem = function(item, response, status) {
        vm.uploading = false;

        if (status === 400) {
            toastr.error('ERROR UPLOADING: ' + response.error.message);
            return;
        }

        toastr.error('ERROR UPLOADING: ' + status);
    };
    
    vm.certUploader = new FileUploader({
        url: '/config/data/' + nodeName + '?t=cert',
        method: 'PUT',
        queueLimit: 1,
        removeAfterUpload: true
    });
    vm.keyUploader = new FileUploader({
        url: '/config/data/' + nodeName + '?t=pkey',
        method: 'PUT',
        queueLimit: 1,
        removeAfterUpload: true
    });
    vm.certUploader.onErrorItem = this.onErrorItem;
    vm.keyUploader.onErrorItem = this.onErrorItem;
    vm.certUploader.onSuccessItem = (item) => {
        vm.keyUploader.uploadAll();
    };
    vm.keyUploader.onSuccessItem = (item) => {
        vm.uploading = false;
        toastr.success('CLIENT CERT SET');
        $modalInstance.close('ok');
    };
}

angular.module('mmmispWebui', [])
    .controller('MISPSideConfigController', [
        '$scope', 'MinemeldConfigService', 'MineMeldRunningConfigStatusService',
        'toastr', '$modal', 'ConfirmService', '$timeout',
        MISPSideConfigController
    ])
    .config(['$stateProvider', function($stateProvider) {
        $stateProvider.state('nodedetail.mispinfo', {
            templateUrl: '/extensions/webui/mmmispWebui/misp.miner.info.html',
            controller: 'NodeDetailInfoController',
            controllerAs: 'vm'
        });
    }])
    .run(['NodeDetailResolver', '$state', function(NodeDetailResolver, $state) {
        NodeDetailResolver.registerClass('mmmisp.node.Miner', {
            tabs: [{
                icon: 'fa fa-circle-o',
                tooltip: 'INFO',
                state: 'nodedetail.mispinfo',
                active: false
            },
            {
                icon: 'fa fa-area-chart',
                tooltip: 'STATS',
                state: 'nodedetail.stats',
                active: false
            },
            {
                icon: 'fa fa-asterisk',
                tooltip: 'GRAPH',
                state: 'nodedetail.graph',
                active: false
            }]
        });

        // if a nodedetail is already shown, reload the current state to apply changes
        // we should definitely find a better way to handle this...
        if ($state.$current.toString().startsWith('nodedetail.')) {
            $state.reload();
        }
    }]);
})();
