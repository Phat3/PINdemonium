import React from 'react';
import Modal from 'react-bootstrap/lib/Modal'
 

class InfoModal extends React.Component {

   constructor(){
    super()
    this.closeInfo = this.closeInfo.bind(this)
  }

  // method passed as callback parameter to children components
  // this method will be called when an item on the slider is clicked
  closeInfo(id, startDump, endDump){
    this.props.closeInfo()
  }

  render () {

     var items = [] 
     //create an item for each dump
    for (var i = 0; i < 10 ; i++) {
      // create the component with the proper prop
      items.push(<li>{"import " + i}</li>)   
    }

    if(this.props.dump){

      return (
        <div>
         <Modal show={this.props.show} onHide={this.closeInfo} bsSize="large" >
            <Modal.Header closeButton>
              <Modal.Title>{"DUMP " + this.props.dump.numbers}</Modal.Title>
            </Modal.Header>
            <Modal.Body>
            
              <hr />
              <h4> Yara Rules</h4>
              
              <p>Duis mollis, est non commodo luctus, nisi erat porttitor ligula.</p>

              <hr />
              <h4> Entropy</h4>
              
              <p>Duis mollis, est non commodo luctus, nisi erat porttitor ligula.</p>

              <hr />
              <h4> Long jump</h4>
              
              <p>Duis mollis, est non commodo luctus, nisi erat porttitor ligula.</p>

              <hr />
              <h4> Jump outer section</h4>
              
              <p>Duis mollis, est non commodo luctus, nisi erat porttitor ligula.</p>

              <hr />

              <h4>Detected imports</h4>

              <ul>
                {items}
              </ul>

            </Modal.Body>
          </Modal>
        </div>
      );

    }

    else{
      return (<div></div>)
    }
    
  }
}

export default InfoModal;
