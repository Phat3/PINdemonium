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


    if(this.props.dump){

      var items = [] 
     
       //create an item for each dump
      for (var i = 0; i < this.props.dump.imports.length; i++) {
        // create the component with the proper prop
        items.push(<li>{ this.props.dump.imports[i].func + " : " + this.props.dump.imports[i].mod }</li>)   
      }

      var heu = []

      for (var i = 0; i < this.props.dump.heuristics.length; i++) {
        var curHeu = this.props.dump.heuristics[i]
        switch (curHeu.name){
          case "LongJumpHeuristic" :
                heu.push(<hr />)
                heu.push(<h4> Long jump {curHeu.result ? <span style={{color : "green"}}>(DETECTED)</span> : <span style={{color : "red"}}>(NOT DETECTED)</span>}</h4>)
                heu.push(<p>{"0x" + curHeu.prev_ip.toString(16)} -> {"0x" + this.props.dump.eip.toString(16)}</p>)
                break;
          case "EntropyHeuristic" :
                heu.push(<hr />)
                heu.push(<h4> Entropy {curHeu.result ? <span style={{color : "green"}}>(DETECTED)</span> : <span style={{color : "red"}}>(NOT DETECTED)</span>}</h4>)
                heu.push(<p>{curHeu.current_entropy} ( {curHeu.difference_entropy_percentage * 100} % )</p>)
                break;
          case "JumpOuterSectionHeuristic" :
                heu.push(<hr />)
                heu.push(<h4> Jump outer section {curHeu.result ? <span style={{color : "green"}}>(DETECTED)</span> : <span style={{color : "red"}}>(NOT DETECTED)</span>}</h4>)
                heu.push(<p>{curHeu.prev_section} -> {curHeu.current_section}</p>)
                break;
          case "YaraRulesHeuristic" : 
                heu.push(<hr />)
                heu.push(<h4>Yara Rules {curHeu.result ? <span style={{color : "green"}}>(DETECTED)</span> : <span style={{color : "red"}}>(NOT DETECTED)</span>}</h4>)
                var rules = []
                for (var j = 0; j < curHeu.matched_rules.length; j++) {
                  rules.push(<li>{curHeu.matched_rules[j]}</li>)
                }
                heu.push(<p><ul>{rules}</ul></p>)
                break;
          default : 
                break;

        }
        // create the component with the proper prop
        items.push(<li>{ "function :" }</li>)   
      }

      return (
        <div>
         <Modal show={this.props.show} onHide={this.closeInfo} bsSize="large" >
            <Modal.Header closeButton>
              <Modal.Title>{"DUMP " + this.props.dump.number}</Modal.Title>
            </Modal.Header>
            <Modal.Body>
            
              {heu}

              <hr />

              <h4>Detected imports ({this.props.dump.reconstructed_imports})</h4>

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
