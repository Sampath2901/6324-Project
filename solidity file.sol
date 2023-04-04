pragma solidity 0.8.19;


abstract contract Ownable {
    address public owner1;
    address public owner2;

    constructor (address __owner1, address __owner2) {
        require(__owner1 != address(0), "Zero");
        owner1 = __owner1;
        owner2 = __owner2;
    }
}

contract ABC is Ownable {

    address public owner3;

    constructor(address _owner1, address _owner2) Ownable(_owner1, _owner2) {
        owner3 = _owner1;
    }
}