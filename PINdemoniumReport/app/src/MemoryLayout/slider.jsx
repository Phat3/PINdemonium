import React from 'react';

import SliderItem from './sliderItem.jsx'


class Slider extends React.Component {

   constructor(){
    super()
    // keep trackof the highlighted "dot"
    this.state = { activeItem : -2 }

    this._analyzeDump = this._analyzeDump.bind(this)
    this._inspectLookahead = this._inspectLookahead.bind(this)

    this.navigateToEmptyMemory = this.navigateToEmptyMemory.bind(this)
    this.navigateToSingleDump = this.navigateToSingleDump.bind(this)
    this.navigateToIntraWriteSetDump = this.navigateToIntraWriteSetDump.bind(this)
    this.navigateToConsecutiveDump = this.navigateToConsecutiveDump.bind(this)
  }

  // method passed as callback parameter to children components
  // this method will be called when an item on the slider is clicked
  navigateToEmptyMemory(id, startDump, endDump){
    this.setState({ activeItem : id })
    this.props.onEmptyMemory()
  }

  // method passed as callback parameter to children components
  // this method will be called when an item on the slider is clicked
  navigateToSingleDump(id, startDump, endDump){
    this.setState({ activeItem : id })
    this.props.onSingleDump(startDump)
  }

  // method passed as callback parameter to children components
  // this method will be called when an item on the slider is clicked
  navigateToIntraWriteSetDump(id, startDump, endDump){
    this.setState({ activeItem : id })
    this.props.onIntraWriteSetDump(startDump)
  }

  // method passed as callback parameter to children components
  // this method will be called when an item on the slider is clicked
  navigateToConsecutiveDump(id, startDump, endDump){
    this.setState({ activeItem : id })
    this.props.onConsecutiveDumps(startDump, endDump)
  }

  _analyzeDump(dumpsToBeAnalyzed, items){

    if(dumpsToBeAnalyzed.length > 1){

     var dump =  dumpsToBeAnalyzed[0]
     var dumpLookahead = dumpsToBeAnalyzed[1]
     //console.log(dump.number)
     
     if(dump.intra_writeset){
        items.push(<SliderItem key={dump.number} id={dump.number} onSelect={this.navigateToIntraWriteSetDump} active={dump.number === this.state.activeItem ? true : false} endDump={undefined} startDump={dump.number} />)  
        this._inspectLookahead(dump, dumpLookahead, items, dumpsToBeAnalyzed) 
      }
      else if(dump.number + 1 == dumpLookahead.number && dumpLookahead.intra_writeset === false){
        items.push(<SliderItem key={dump.number} id={dump.number} onSelect={this.navigateToConsecutiveDump} active={dump.number === this.state.activeItem ? true : false} endDump={dumpLookahead.number} startDump={dump.number} />)
        //console.log(dump.number)
        //dumpsToBeAnalyzed.shift()
        //this._inspectLookahead(dump, dumpLookahead, items, dumpsToBeAnalyzed) 
      }
      else{
        // create the component with the proper prop
        items.push(<SliderItem key={dump.number} id={dump.number} onSelect={this.navigateToSingleDump} active={dump.number === this.state.activeItem ? true : false} endDump={undefined} startDump={dump.number} />)   
        this._inspectLookahead(dump, dumpLookahead, items) 
      }
      
      dumpsToBeAnalyzed.shift()
      this._analyzeDump(dumpsToBeAnalyzed, items)

    }
    else if(dumpsToBeAnalyzed.length === 1){
       var dump =  dumpsToBeAnalyzed[0]
      items.push(<SliderItem key={dump.number} id={dump.number} onSelect={this.navigateToSingleDump} active={dump.number === this.state.activeItem ? true : false} endDump={undefined} startDump={dump.number} />)   
    }

  }

  _inspectLookahead(dump, dumpLookahead, items, dumpsToBeAnalyzed){
    var specialDumpId = dump.number + 400
    if(dump.number + 1 === dumpLookahead.number && dumpLookahead.intra_writeset === false){
      if(dumpsToBeAnalyzed !== undefined){
           dumpsToBeAnalyzed.shift()
      }
      items.push(<SliderItem key={specialDumpId} id={specialDumpId} onSelect={this.navigateToConsecutiveDump} active={specialDumpId === this.state.activeItem ? true : false} endDump={dumpLookahead.number} startDump={dump.number} />)   
    }
  }

  render () {

    var olStyle = {
        listStyle : 'none',
        width : '100%',
        textAlign : 'center',
        paddingLeft : '0px',
        paddingTop : '20px',
        paddingBottom : '10px'
    }
    /*
    var items = this.props.data.map(function(row){
      return <RegisterRow key={row.id} name={row.name} content={row.content}/>
    })
    */
    var items = [
      <SliderItem key={-2} id={-2} onSelect={this.navigateToEmptyMemory} active={this.state.activeItem === -2 ? true : false} endDump={undefined} startDump={undefined} />,
      <SliderItem key={-1} id={-1} onSelect={this.navigateToSingleDump} active={this.state.activeItem === -1 ? true : false} endDump={undefined} startDump={0} />
    ]    
    
    var currentDumps = this.props.dumps.slice()
    //currentDumps.shift()

    this._analyzeDump(currentDumps, items)

    return (
      <div>
         <ol style={olStyle}>
             {items}
          </ol>
      </div>
    );
  }
}

Slider.propTypes = {
  onEmptyMemory: React.PropTypes.func.isRequired,
  onSingleDump: React.PropTypes.func.isRequired,
  onConsecutiveDumps: React.PropTypes.func.isRequired,
  onIntraWriteSetDump: React.PropTypes.func.isRequired 
}

export default Slider;
