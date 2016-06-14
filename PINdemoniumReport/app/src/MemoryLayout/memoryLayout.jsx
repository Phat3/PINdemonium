import React from 'react';

import Slider from './slider.jsx'


class MemoryLayout extends React.Component {

  constructor(){
    super()
    this._setHeight = this._setHeight.bind(this)
    this._drawMemory = this._drawMemory.bind(this)
    this._drawDump = this._drawDump.bind(this)
    this._drawArrow = this._drawArrow.bind(this)
    this._drawDumps = this._drawDumps.bind(this)
    this.updateMemory = this.updateMemory.bind(this)

  }

  //set the proper dimensions for the canvas object based on the viewport dimension
  _setHeight(){
    var navbarHeight = document.getElementById('navbar').offsetHeight;
    var informationHeight = document.getElementById('information').offsetHeight;
    var sliderHeight = document.getElementById('slider').offsetHeight;

    this.canvas.width = window.innerWidth - 30;
    this.canvas.height = window.innerHeight - (navbarHeight + informationHeight + sliderHeight + 50);
  }

  _drawMemory(){
    // draw the rectangle representing the memory of the process
    var memorySpace = new createjs.Shape();
    memorySpace.width = this.canvas.width / 3
    memorySpace.height = this.canvas.height - 52 
    memorySpace.x = memorySpace.width
    memorySpace.y = 50
    memorySpace.graphics.setStrokeStyle(2).beginStroke("rgba(0,0,0,1)").beginFill("DeepSkyBlue").drawRect(0, 0, memorySpace.width, memorySpace.height);

    // draw the label above the rectangle representing the process
    var labelMemorySpace = new createjs.Text("Memory Layout", "30px Arial", "black");
    // center the label on the rectangle
    var labelMemorySpaceBounds = labelMemorySpace.getBounds()
    labelMemorySpace.x = memorySpace.width + ( (memorySpace.width - labelMemorySpaceBounds.width) / 2)

    // draw the addresses label on the right of the memory layout
    var labelMemoryFirstAddress = new createjs.Text("0x00", "20px Arial", "red");
    var labelMemoryLastAddress = new createjs.Text("0xff", "20px Arial", "red");
    var labelmemoryAddressX = memorySpace.width * 2 + 10
    labelMemoryFirstAddress.x = labelmemoryAddressX
    labelMemoryFirstAddress.y = 50
    labelMemoryLastAddress.x = labelmemoryAddressX
    labelMemoryLastAddress.y = memorySpace.height - (labelMemoryLastAddress.getBounds().height) + 50

    // draw the main module
    var mainModule = new createjs.Shape();
    mainModule.width = memorySpace.width
    mainModule.height = memorySpace.height / 3
    mainModule.x = memorySpace.x
    mainModule.y = memorySpace.y + mainModule.height
    mainModule.graphics.setStrokeStyle(2).beginStroke("rgba(0,0,0,1)").beginFill("yellowGreen").drawRect(0, 0, mainModule.width, mainModule.height);

    // draw the label for the main module
    var labelMainModule = new createjs.Text("Main module", "25px Arial", "black");
    var labelMainModuleBounds = labelMainModule.getBounds()
    labelMainModule.x = mainModule.width + ( (mainModule.width - labelMainModuleBounds.width) / 2)
    labelMainModule.y = mainModule.y + 50

    // draw the addresses label on the right of the main module
    var labelMainModuleStartAddress = new createjs.Text("0x" + this.props.information.main_module.start_address.toString(16), "20px Arial", "green");
    var labelMainModuleEndAddress = new createjs.Text("0x" + this.props.information.main_module.end_address.toString(16), "20px Arial", "green");
    var labelMainModuleAddressX = mainModule.x + mainModule.width + 10
    labelMainModuleStartAddress.x = labelMainModuleAddressX
    labelMainModuleStartAddress.y =  mainModule.y - (labelMainModuleEndAddress.getBounds().height / 2 )
    labelMainModuleEndAddress.x = labelMainModuleAddressX
    labelMainModuleEndAddress.y = labelMainModuleStartAddress.y + mainModule.height

    var aboveHeap = new createjs.Shape();
    aboveHeap.width = memorySpace.width
    aboveHeap.height = memorySpace.height / 6
    aboveHeap.x = memorySpace.x
    aboveHeap.y = mainModule.y - aboveHeap.height - 50
    aboveHeap.graphics.setStrokeStyle(2).beginStroke("rgba(0,0,0,1)").beginFill("orange").drawRect(0, 0, aboveHeap.width, aboveHeap.height);

    // draw the addresses label on the right of the main module
    var labelAboveHeapStartAddress = new createjs.Text("0x" + this.props.information.main_module.start_address.toString(16), "20px Arial", "green");
    var labelAboveHeapEndAddress = new createjs.Text("0x" + this.props.information.main_module.end_address.toString(16), "20px Arial", "green");
    var labelAboveHeapAddressX = aboveHeap.x + aboveHeap.width + 10
    labelAboveHeapStartAddress.x = labelAboveHeapAddressX
    labelAboveHeapStartAddress.y =  aboveHeap.y - (labelAboveHeapEndAddress.getBounds().height / 2 )
    labelAboveHeapEndAddress.x = labelAboveHeapAddressX
    labelAboveHeapEndAddress.y = labelAboveHeapStartAddress.y + aboveHeap.height

    var underHeap = new createjs.Shape();
    underHeap.width = memorySpace.width
    underHeap.height = memorySpace.height / 6
    underHeap.x = memorySpace.x
    underHeap.y = mainModule.y + mainModule.height + 50
    underHeap.graphics.setStrokeStyle(2).beginStroke("rgba(0,0,0,1)").beginFill("orange").drawRect(0, 0, underHeap.width, underHeap.height);

    // draw the addresses label on the right of the main module
    var labelUnderHeapStartAddress = new createjs.Text("0x" + this.props.information.main_module.start_address.toString(16), "20px Arial", "green");
    var labelUnderHeapEndAddress = new createjs.Text("0x" + this.props.information.main_module.end_address.toString(16), "20px Arial", "green");
    var labelUnderHeapAddressX = underHeap.x + underHeap.width + 10
    labelUnderHeapStartAddress.x = labelUnderHeapAddressX
    labelUnderHeapStartAddress.y =  underHeap.y - (labelUnderHeapEndAddress.getBounds().height / 2 )
    labelUnderHeapEndAddress.x = labelUnderHeapAddressX
    labelUnderHeapEndAddress.y = labelUnderHeapStartAddress.y + underHeap.height

    // draw the label for the main module
    var labelAboveHeap = new createjs.Text("Heap 1", "25px Arial", "black");
    var labelAboveHeapBounds = labelAboveHeap.getBounds()
    labelAboveHeap.x = aboveHeap.x + ( (aboveHeap.width - labelAboveHeapBounds.width) / 2)
    labelAboveHeap.y = aboveHeap.y + 50

    // draw the label for the main module
    var labelUnderHeap = new createjs.Text("Heap 2", "25px Arial", "black");
    var labelUnderHeapBounds = labelUnderHeap.getBounds()
    labelUnderHeap.x = underHeap.x + ( (underHeap.width - labelUnderHeapBounds.width) / 2)
    labelUnderHeap.y = underHeap.y + 50

    this.stage.addChild(memorySpace, labelMemorySpace, labelMemoryFirstAddress, labelMemoryLastAddress, mainModule, labelMainModule, labelMainModuleStartAddress, labelMainModuleEndAddress, aboveHeap, underHeap, labelAboveHeapStartAddress, labelAboveHeapEndAddress, labelUnderHeapStartAddress, labelUnderHeapEndAddress, labelUnderHeap, labelAboveHeap);
    // update the canvas
    this.stage.update();
  }

  _drawDumps(startDumpIndex, endDumpIndex){

    var startDump = this.props.dumps[startDumpIndex]
    var endDump = this.props.dumps[endDumpIndex]

    if(startDump.start_address < endDump.start_address){
        this._drawDump(100, startDump, "DUMP_1")
        this._drawDump(400, endDump, "DUMP_2")
    }
    else{
        this._drawDump(400, startDump, "DUMP_1")
        this._drawDump(100, endDump, "DUMP_2")
    }

     this._drawArrow(endDump.eip)
  }


  _drawDump(y, dump, name){
    // draw the rectangle representing the memory of the process
    var dumpShape = new createjs.Shape()
    dumpShape.name = name
    dumpShape.width = this.canvas.width / 2.5
    dumpShape.height = 100
    dumpShape.x = (this.canvas.width - dumpShape.width)/2
    dumpShape.y = y
    dumpShape.graphics.setStrokeStyle(4).beginStroke("#4caf50").beginFill("red").drawRect(0, 0, dumpShape.width, dumpShape.height);
    
    // draw the label above the rectangle representing the process
    var labelDumpShape = new createjs.Text(name, "30px Arial", "white");
    // center the label on the rectangle
    var labelDumpShapeBounds = labelDumpShape.getBounds()
    labelDumpShape.x = dumpShape.x + ( (dumpShape.width - labelDumpShapeBounds.width) / 2)
    labelDumpShape.y = dumpShape.y + ( ( dumpShape.height - labelDumpShapeBounds.height) / 2)
    
    // draw the addresses label on the right of the memory layout
    var labelDumpShapeFirstAddress = new createjs.Text("0x" + dump.start_address.toString(16), "20px Arial", "blue");
    var labelDumpShapeLastAddress = new createjs.Text("0x" + dump.end_address.toString(16), "20px Arial", "blue");
    labelDumpShapeFirstAddress.x = dumpShape.width + dumpShape.x + 10
    labelDumpShapeFirstAddress.y = dumpShape.y
    labelDumpShapeLastAddress.x = dumpShape.width + dumpShape.x + 10
    labelDumpShapeLastAddress.y = dumpShape.y +   dumpShape.height - (labelDumpShapeLastAddress.getBounds().height)

    this.dumpsContainer.addChild(dumpShape, labelDumpShape, labelDumpShapeFirstAddress, labelDumpShapeLastAddress);
    // update the canvas
    this.stage.update();
  }

  _drawArrow(oep){

    var dump_1 = this.dumpsContainer.getChildByName("DUMP_1")
    var dump_2 = this.dumpsContainer.getChildByName("DUMP_2")

    var beginArrowX = dump_1.x - 2
    var beginArrowY = dump_1.y + (dump_1.height / 2)
    var leftOffsetArrow = 60
    var middleArriveDumpY = dump_2.y + (dump_2.height / 2)
    var arrow = new createjs.Shape();
    arrow.name = "arrow"
    arrow.graphics.setStrokeStyle(4)
                  .beginStroke("magenta")

                  .moveTo(beginArrowX, beginArrowY)                             // move the corsor on the left border of the start dump
                                                                                // and in the middle of its height
                  
                  .lineTo(beginArrowX - leftOffsetArrow, beginArrowY)           // draw a straight horizontal segment 60px on the left

                  .lineTo(beginArrowX - leftOffsetArrow, middleArriveDumpY)     // draw a straight vertical line until the middle of the arrive dump

                  .lineTo(beginArrowX, middleArriveDumpY)                       // draw a straight horizontal line until the left border of the final dump

                  .moveTo(beginArrowX - 25,  middleArriveDumpY - 13)            // draw the arrowhead

                  .lineTo(beginArrowX, middleArriveDumpY)                       // draw the arrowhead

                  .lineTo(beginArrowX - 25,  middleArriveDumpY + 13)            // draw the arrowhead
    

    // place the label that display the OEP on the left of the label
    var labelOEP = new createjs.Text("OEP : 0x" + oep.toString(16), "20px Arial", "green");
    labelOEP.x = beginArrowX - leftOffsetArrow - labelOEP.getBounds().width - 10
    labelOEP.y = middleArriveDumpY - (labelOEP.getBounds().height / 2)

    this.dumpsContainer.addChild(arrow, labelOEP);
    this.stage.update();

  }

  //callback of reactjs called when th component mounting is finished
  componentDidMount() {
    // set the canvas dimension on the view port
    this.canvas = document.getElementById('memoryLayoutCanvas'); 
    this._setHeight() 
    this.stage = new createjs.Stage("memoryLayoutCanvas");
    //draw the memory layout
    this._drawMemory()
    // create another "layer" for the dumps
    this.dumpsContainer = new createjs.Container()
    this.stage.addChild(this.dumpsContainer)
    // draw the initial situation (INDEX (-1,-1) IS THE INITIAL SITUATION!!!)
    //this._drawDumps(-1,-1)
  }

  // update the canvas in order to visualize the new dumps situation
  updateMemory(startDump, endDump){
    //clear the old canvas
    this.dumpsContainer.removeAllChildren()
    this.stage.update()
    // idf both the index are -1 we want to see the initial situation
    if(startDump !== -1 && endDump !== -1){
      //draw the new one
      this._drawDumps(startDump, endDump)
    }
     
  }

  render () {

    var highlightBorder = {
      marginTop: '15px',
      borderTop : '#f33901 1px solid'
    }
    // if the report contains no dump then don't show the slider 
    var slider = this.props.dumps.length === 0 ? <h3>Sorry there are no dump in this report...</h3> : <Slider dumps={this.props.dumps} onUpdate={this.updateMemory}/>

    return (
      <div>
        <canvas id="memoryLayoutCanvas"></canvas>

        <div className="row" id="slider" style={highlightBorder}>
            <div className="col-sm-12" style={{textAlign : 'center'}}>
                {slider}
            </div>
        </div>
      </div>
    );

  }

}

export default MemoryLayout;






